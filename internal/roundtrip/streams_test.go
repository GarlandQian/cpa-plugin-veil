package roundtrip

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// These two need an interleaving the interface cannot arrange: they hold a
// stream's count open while another call arrives.

func TestStreamChunkAndReplacementAreSerialized(t *testing.T) {
	v := vault.New(make([]byte, 32), 100)
	placeholder := v.Placeholder("scope", "EMAIL", "alice@example.test")
	r := newStreamRestorer(v)
	var finished atomic.Int64
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Go(func() {
			for n := 0; n < 20; n++ {
				// Several callers intentionally race on each request ID. Chunk and
				// finish must never mutate a Stream at the same time.
				c := streamCall{scope: "scope", requestID: fmt.Sprintf("r%d", worker%4), init: true}
				r.chunk(c, func(*restore.Tally) { finished.Add(1) })
				c.init = false
				c.body = []byte(deltaEvent(placeholder + " ok"))
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

// Completion may be reporting its tally while the same request opens a
// stream again. The new one waits for it, and holds as any other.
func TestCompletedStreamDoesNotDegradeItsSuccessor(t *testing.T) {
	v := vault.New(make([]byte, 32), 100)
	placeholder := v.Placeholder("scope", "EMAIL", "alice@example.test")
	r := newStreamRestorer(v)
	defer r.close()
	finishing, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	call := streamCall{scope: "scope", requestID: "same", init: true}
	r.chunk(call, func(*restore.Tally) { close(finishing); <-resume })
	completed := make(chan struct{})
	go func() {
		c := call
		c.init = false
		c.body = []byte(stopLine)
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
		c.body = []byte(deltaEvent(piece))
		out = append(out, r.chunk(c, nil)...)
	}
	if got := streamedText(t, string(out)); got != "alice@example.test ok" {
		t.Fatalf("successor stopped holding: %q", got)
	}
}
