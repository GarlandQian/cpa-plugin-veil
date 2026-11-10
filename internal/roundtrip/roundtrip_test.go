package roundtrip

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

const (
	email    = "alice@example.test"
	stopLine = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
)

// world is Trips with what a test needs around them: the Vault they restore
// from, a Store to keep records in, and a clock the test moves.
type world struct {
	t     *testing.T
	trips *Trips
	vault *vault.Vault
	store *records.Store
	now   time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, vault: vault.New(make([]byte, 32), 100), store: records.New(), now: time.Now()}
	w.trips = New(w.vault)
	w.trips.streams.now = func() time.Time { return w.now }
	t.Cleanup(func() {
		w.trips.Close()
		w.store.Close()
	})
	return w
}

// request is a request of scope that left a Masking record, known to the
// Trips by id. It returns the record's key and the Placeholder the request's
// value went out as.
func (w *world) request(scope, id string) (key int64, placeholder string) {
	w.t.Helper()
	placeholder = w.vault.Placeholder(scope, "EMAIL", email)
	ref, ok := w.store.Add(records.Record{Time: time.Now(), Caller: scope})
	if !ok {
		w.t.Fatal("the record was not kept")
	}
	w.trips.Recorded(scope, id, ref)
	return ref.Key, placeholder
}

// restored is what the record of key says its response put back; nil while
// no response has ended.
func (w *world) restored(key int64) *records.Restored {
	w.t.Helper()
	w.store.Flush()
	all, _ := w.store.List(0, 100, records.Filter{})
	for _, r := range all {
		if r.Key == key {
			return r.Restored
		}
	}
	w.t.Fatalf("no record %d", key)
	return nil
}

func deltaEvent(text string) string {
	b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": text}})
	return "event: content_block_delta\ndata: " + string(b) + "\n\n"
}

// streamedText joins the text of a stream's deltas.
func streamedText(t *testing.T, stream string) string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(stream, "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			t.Fatalf("bad data line %q", line)
		}
		b.WriteString(ev.Delta.Text)
	}
	return b.String()
}

func waitFor(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("the test did not reach the expected point")
		}
		runtime.Gosched()
	}
}

// A response is its request's by the request ID within the Caller scope, and
// only the first response of a request counts.
func TestAResponseCountsOnceInItsOwnRequestsRecord(t *testing.T) {
	w := newWorld(t)
	keyA, placeholderA := w.request("caller-a", "same-id")
	keyB, placeholderB := w.request("caller-b", "same-id")
	// A Pass that kept no record leaves the one an earlier Pass kept.
	w.trips.Recorded("caller-a", "same-id", records.Ref{})

	w.trips.Respond("caller-c", "same-id", []byte(`{"text":"`+placeholderA+`"}`))
	if w.restored(keyA) != nil || w.restored(keyB) != nil {
		t.Fatal("another caller's response counted")
	}
	for _, tt := range []struct {
		scope, placeholder string
		key                int64
	}{{"caller-a", placeholderA, keyA}, {"caller-b", placeholderB, keyB}} {
		body := []byte(`{"text":"` + tt.placeholder + `"}`)
		if out := w.trips.Respond(tt.scope, "same-id", body); !strings.Contains(string(out), email) {
			t.Fatalf("%s: not restored: %s", tt.scope, out)
		}
		w.trips.Respond(tt.scope, "same-id", body)
		if got := w.restored(tt.key); got == nil || got.Back[tt.placeholder] != 1 {
			t.Fatalf("%s: restored = %+v", tt.scope, got)
		}
	}
}

// A stream counts what it put back once, however it ends: with the event that
// ends it, when its request opens another, when it has been idle too long, or
// when the instance shuts down.
func TestAStreamCountsOnceHoweverItEnds(t *testing.T) {
	for _, exit := range []string{"completion", "replacement", "timeout", "shutdown"} {
		t.Run(exit, func(t *testing.T) {
			w := newWorld(t)
			key, placeholder := w.request("scope", "r1")
			w.trips.Open("scope", "r1")
			// An empty chunk still takes its place in the order.
			w.trips.Chunk("scope", "r1", 0, nil)
			if out := w.trips.Chunk("scope", "r1", 1, []byte(deltaEvent(placeholder+" ok"))); !strings.Contains(string(out), email) {
				t.Fatalf("not restored: %s", out)
			}
			if got := w.restored(key); got != nil {
				t.Fatalf("counted before the stream ended: %+v", got)
			}
			switch exit {
			case "completion":
				w.trips.Chunk("scope", "r1", 2, []byte(stopLine))
			case "replacement":
				w.trips.Open("scope", "r1")
			case "timeout":
				w.now = w.now.Add(streamIdleTimeout + time.Second)
				w.trips.Open("scope", "r2")
			case "shutdown":
				w.trips.Close()
			}
			w.trips.Close()
			w.trips.Close()
			w.trips.Open("scope", "r1")
			if got := w.restored(key); got == nil || got.Back[placeholder] != 1 {
				t.Fatalf("restored = %+v", got)
			}
		})
	}
}

// A stream holds a Placeholder cut across its chunks, and two requests alike
// in everything but their IDs are two streams.
func TestStreamsOfDifferentRequestsDoNotMix(t *testing.T) {
	w := newWorld(t)
	placeholder := w.vault.Placeholder("scope", "EMAIL", email)
	out := map[string][]byte{"a": nil, "b": nil}
	for id := range out {
		w.trips.Open("scope", id)
	}
	for i, piece := range []string{" to ", placeholder[:7], placeholder[7:], " ok"} {
		for id := range out {
			if i == 0 {
				piece = id + " to "
			}
			out[id] = append(out[id], w.trips.Chunk("scope", id, i, []byte(deltaEvent(piece)))...)
		}
	}
	for id := range out {
		out[id] = append(out[id], w.trips.Chunk("scope", id, 4, []byte(stopLine))...)
		if got := streamedText(t, string(out[id])); got != id+" to "+email+" ok" {
			t.Fatalf("%s = %q", id, got)
		}
	}
}

// A call that names no request belongs to no Round trip. Its response is
// restored, a chunk on its own, and nothing is counted.
func TestACallThatNamesNoRequestIsRestoredAndNotCounted(t *testing.T) {
	w := newWorld(t)
	key, placeholder := w.request("scope", "")
	if out := w.trips.Respond("scope", "", []byte(`{"text":"`+placeholder+`"}`)); !strings.Contains(string(out), email) {
		t.Fatalf("response not restored: %s", out)
	}
	w.trips.Open("scope", "")
	if out := w.trips.Chunk("scope", "", 0, []byte(deltaEvent("to "+placeholder))); !strings.Contains(string(out), email) {
		t.Fatalf("a whole Placeholder was not restored: %s", out)
	}
	cut := string(w.trips.Chunk("scope", "", 1, []byte(deltaEvent(placeholder[:7])))) + string(w.trips.Chunk("scope", "", 2, []byte(deltaEvent(placeholder[7:]))))
	if got := streamedText(t, cut); got != placeholder {
		t.Fatalf("a chunk waited for the next: %q", got)
	}
	w.trips.Chunk("scope", "", 3, []byte(stopLine))
	if got := w.restored(key); got != nil {
		t.Fatalf("counted: %+v", got)
	}
}
