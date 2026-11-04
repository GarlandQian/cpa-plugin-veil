package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

func TestStreamFinishesOnceOnEveryExit(t *testing.T) {
	for _, exit := range []string{"completion", "replacement", "timeout", "shutdown"} {
		t.Run(exit, func(t *testing.T) {
			v := vault.New(make([]byte, 32), 100)
			placeholder := v.Placeholder("scope", "EMAIL", "alice@example.test")
			r := newStreamRestorer(v)
			defer r.close()
			now := time.Now()
			r.now = func() time.Time { return now }
			finished := 0
			r.chunk(streamCall{scope: "scope", requestID: "r1", init: true}, func(tally *restore.Tally) {
				finished++
				if tally.Back[placeholder] != 1 {
					t.Errorf("final tally: %+v", tally)
				}
			})
			// One empty chunk must not break the next chunk's sequence.
			r.chunk(streamCall{scope: "scope", requestID: "r1", index: 0}, nil)
			out := r.chunk(streamCall{scope: "scope", requestID: "r1", index: 1, body: []byte(strings.Join(deltaEvent(placeholder+" ok"), ""))}, nil)
			if !strings.Contains(string(out), "alice@example.test") {
				t.Fatalf("not restored: %s", out)
			}
			if finished != 0 {
				t.Fatal("finished before stream ended")
			}
			switch exit {
			case "completion":
				r.chunk(streamCall{scope: "scope", requestID: "r1", index: 2, body: []byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")}, nil)
			case "replacement":
				r.chunk(streamCall{scope: "scope", requestID: "r1", init: true}, nil)
			case "timeout":
				now = now.Add(streamIdleTimeout + time.Second)
				r.chunk(streamCall{scope: "scope", requestID: "r2", init: true}, nil)
			case "shutdown":
				r.close()
			}
			r.close()
			r.close()
			r.chunk(streamCall{scope: "scope", requestID: "r1", init: true}, func(*restore.Tally) { t.Error("closed restorer reopened") })
			if finished != 1 {
				t.Fatalf("finished %d times", finished)
			}
		})
	}
}

func TestAmbiguousLegacyStreamsSkipTheirTallies(t *testing.T) {
	v := vault.New(make([]byte, 32), 100)
	placeholder := v.Placeholder("scope", "TERM", "fixture")
	r := newStreamRestorer(v)
	defer r.close()
	call := streamCall{scope: "scope", requestBody: []byte("same"), init: true}
	r.chunk(call, func(*restore.Tally) { t.Error("first ambiguous stream reported a tally") })
	// The first header has already consumed its record link when the second
	// request arrives, so the stream registry must detect this ambiguity too.
	r.chunk(call, func(*restore.Tally) { t.Error("second ambiguous stream reported a tally") })
	call.init = false
	for n := 0; n < 2; n++ {
		call.index = 0
		call.body = []byte(strings.Join(deltaEvent(placeholder+" ok"), ""))
		if out := r.chunk(call, nil); !strings.Contains(string(out), "fixture") {
			t.Fatalf("ambiguous stream stopped restoring: %s", out)
		}
		call.index = 1
		call.body = []byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		r.chunk(call, nil)
	}
	r.close()
}

func TestStreamChunkAndReplacementAreSerialized(t *testing.T) {
	v := vault.New(make([]byte, 32), 100)
	placeholder := v.Placeholder("scope", "EMAIL", "alice@example.test")
	r := newStreamRestorer(v)
	var finished atomic.Int64
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Go(func() {
			for n := 0; n < 20; n++ {
				// Several callers intentionally race on each request ID. Chunk, finish
				// and StopHolding must never mutate a Stream at the same time.
				c := streamCall{scope: "scope", requestID: fmt.Sprintf("r%d", worker%4), init: true}
				r.chunk(c, func(*restore.Tally) { finished.Add(1) })
				c.init = false
				c.body = []byte(strings.Join(deltaEvent(placeholder+" ok"), ""))
				r.chunk(c, nil)
			}
		})
	}
	wg.Wait()
	r.close()
	if got := finished.Load(); got != 16*20 {
		t.Fatalf("finished %d of %d streams", got, 16*20)
	}
}

// Completion may be reporting its tally while the next request with the same
// body opens. A completed stream must not force the new one to stop holding.
func TestCompletedStreamDoesNotDegradeItsSuccessor(t *testing.T) {
	v := vault.New(make([]byte, 32), 100)
	placeholder := v.Placeholder("scope", "EMAIL", "alice@example.test")
	r := newStreamRestorer(v)
	defer r.close()
	finishing, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	call := streamCall{scope: "scope", requestBody: []byte("same"), init: true}
	r.chunk(call, func(*restore.Tally) { close(finishing); <-resume })
	completed := make(chan struct{})
	go func() {
		c := call
		c.init = false
		c.body = []byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		r.chunk(c, nil)
		close(completed)
	}()
	<-finishing
	opened := make(chan struct{})
	go func() { r.chunk(call, nil); close(opened) }()
	waitFor(t, func() bool {
		if r.mu.TryLock() {
			r.mu.Unlock()
			return false
		}
		return true
	})
	release()
	<-completed
	<-opened
	var out []byte
	for n, piece := range []string{placeholder[:7], placeholder[7:] + " ok"} {
		c := call
		c.init = false
		c.index = n
		c.body = []byte(strings.Join(deltaEvent(piece), ""))
		out = append(out, r.chunk(c, nil)...)
	}
	if got := streamedText(t, string(out)); got != "alice@example.test ok" {
		t.Fatalf("successor stopped holding: %q", got)
	}
}
