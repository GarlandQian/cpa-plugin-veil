package roundtrip

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
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
	w.trips.now = func() time.Time { return w.now }
	t.Cleanup(func() {
		w.trips.Close()
		w.store.Close()
	})
	return w
}

// found is what a Pass found: the Masking record of a request of scope that
// had values, each by the Placeholder it went out as.
func (w *world) found(scope string, values ...string) (records.Record, []string) {
	rec := records.Record{Time: time.Now(), Caller: scope, Took: 1}
	var placeholders []string
	for _, value := range values {
		placeholder := w.vault.Placeholder(scope, "EMAIL", value)
		placeholders = append(placeholders, placeholder)
		rec.Values = append(rec.Values, records.Value{Placeholder: placeholder, Kind: "EMAIL", N: 1, Action: "mask"})
		rec.N++
	}
	return rec, placeholders
}

// request is a request of scope with one value, known to the Trips by id,
// after its Pass before the Host picks a credential. It returns the
// Placeholder the value went out as.
func (w *world) request(scope, id string) string {
	w.t.Helper()
	rec, placeholders := w.found(scope, email)
	w.trips.Pass(scope, id, true).Keep(w.store, rec)
	return placeholders[0]
}

// records are the Masking records kept so far, the oldest first.
func (w *world) records() []records.Record {
	w.t.Helper()
	w.store.Flush()
	all, _ := w.store.List(0, 100, records.Filter{})
	slices.Reverse(all)
	return all
}

// only is the one Masking record kept so far.
func (w *world) only() records.Record {
	w.t.Helper()
	all := w.records()
	if len(all) != 1 {
		w.t.Fatalf("%d records: %+v", len(all), all)
	}
	return all[0]
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

// A request is one Round trip however many Passes it has: they keep one
// Masking record, with each value once, and a body one of them left needs no
// second look.
func TestThePassesOfARequestKeepOneRecord(t *testing.T) {
	w := newWorld(t)
	first, _ := w.found("scope", email)
	before := w.trips.Pass("scope", "r1", true)
	if before.Left([]byte("as it came")) {
		t.Fatal("a body no Pass has seen was taken as left")
	}
	before.Keep(w.store, first)
	before.Leave([]byte("masked"))

	// Each credential the Host tries hands the request over again, here with
	// text another plugin added, the same every time.
	later, _ := w.found("scope", email, "bob@example.test")
	later.Snips = map[string]string{later.Values[1].Placeholder: "to " + later.Values[1].Placeholder}
	for attempt := range 3 {
		after := w.trips.Pass("scope", "r1", false)
		if !after.Left([]byte("masked")) {
			t.Fatal("the body the Pass before left was looked at again")
		}
		if after.Left([]byte("masked, and more")) != (attempt > 0) {
			t.Fatalf("attempt %d: a body with new text", attempt)
		}
		after.Keep(w.store, later)
		after.Leave(nil)
	}
	got := w.only()
	if got.N != 2 || len(got.Values) != 2 || got.Took != 2 || len(got.Snips) != 1 {
		t.Fatalf("record = %+v", got)
	}
	// A Pass that stops the request says so in the same record, and one that
	// found nothing keeps nothing.
	w.trips.Pass("scope", "r1", false).Keep(w.store, records.Record{Stopped: records.StoppedBlock})
	w.trips.Pass("scope", "r1", false).Keep(w.store, records.Record{})
	if got := w.only(); got.Stopped != records.StoppedBlock || got.N != 2 {
		t.Fatalf("record = %+v", got)
	}
}

// Every request is a Round trip of its own, with a record of its own, even
// one that is the last one sent again. Without a Store nothing is kept.
func TestEveryRequestIsItsOwnRoundTrip(t *testing.T) {
	w := newWorld(t)
	rec, _ := w.found("scope", email)
	for _, id := range []string{"r1", "r2", "r3"} {
		pass := w.trips.Pass("scope", id, true)
		if pass.Left([]byte("the same body")) {
			t.Fatalf("%s: a body another request left was not looked at", id)
		}
		pass.Keep(w.store, rec)
		pass.Leave(nil)
	}
	w.trips.Pass("scope", "r4", true).Keep(nil, rec)
	if got := w.records(); len(got) != 3 {
		t.Fatalf("%d records", len(got))
	}
}

// A response is its request's by the request ID within the Caller scope, and
// only the first response of a request counts.
func TestAResponseCountsOnceInItsOwnRequestsRecord(t *testing.T) {
	w := newWorld(t)
	placeholderA := w.request("caller-a", "same-id")
	placeholderB := w.request("caller-b", "same-id")
	w.trips.Respond("caller-c", "same-id", []byte(`{"text":"`+placeholderA+`"}`))
	for _, r := range w.records() {
		if r.Restored != nil {
			t.Fatalf("another caller's response counted: %+v", r)
		}
	}
	for i, tt := range []struct{ scope, placeholder string }{{"caller-a", placeholderA}, {"caller-b", placeholderB}} {
		body := []byte(`{"text":"` + tt.placeholder + `"}`)
		if out := w.trips.Respond(tt.scope, "same-id", body); !strings.Contains(string(out), email) {
			t.Fatalf("%s: not restored: %s", tt.scope, out)
		}
		w.trips.Respond(tt.scope, "same-id", body)
		if got := w.records()[i].Restored; got == nil || got.Back[tt.placeholder] != 1 {
			t.Fatalf("%s: restored = %+v", tt.scope, got)
		}
	}
}

// A Round trip counts what its stream put back once, however it ends: with
// the event that ends the stream, when the Host says the request is complete,
// with the next Round trip of its request ID, when no call has come for too
// long, or when the instance shuts down.
func TestAStreamCountsOnceHoweverItEnds(t *testing.T) {
	for _, exit := range []string{"the end of the stream", "completion", "the next Round trip", "idleness", "shutdown"} {
		t.Run(exit, func(t *testing.T) {
			w := newWorld(t)
			placeholder := w.request("scope", "r1")
			w.trips.Open("scope", "r1")
			// An empty chunk still takes its place in the order.
			w.trips.Chunk("scope", "r1", 0, nil)
			if out := w.trips.Chunk("scope", "r1", 1, []byte(deltaEvent(placeholder+" ok"))); !strings.Contains(string(out), email) {
				t.Fatalf("not restored: %s", out)
			}
			if got := w.only().Restored; got != nil {
				t.Fatalf("counted before the stream ended: %+v", got)
			}
			switch exit {
			case "the end of the stream":
				w.trips.Chunk("scope", "r1", 2, []byte(stopLine))
			case "completion":
				w.trips.Complete("r1")
			case "the next Round trip":
				w.trips.Pass("scope", "r1", true)
			case "idleness":
				w.now = w.now.Add(idleTimeout + time.Second)
				w.trips.Open("scope", "r2")
			case "shutdown":
				w.trips.Close()
			}
			// Nothing that comes after counts again.
			w.trips.Chunk("scope", "r1", 3, []byte(deltaEvent(placeholder)))
			w.trips.Complete("r1")
			w.trips.Close()
			w.trips.Close()
			w.trips.Open("scope", "r1")
			if got := w.only().Restored; got == nil || got.Back[placeholder] != 1 {
				t.Fatalf("restored = %+v", got)
			}
		})
	}
}

// A stream that put nothing back still says that the response came: its
// record is no longer one waiting for a response. A request that got no
// response at all leaves its record waiting.
func TestAStreamWithNothingToRestoreStillAnswersItsRecord(t *testing.T) {
	w := newWorld(t)
	warned := records.Record{Time: time.Now(), Caller: "scope", N: 1, Values: []records.Value{{Placeholder: "{{PHONE_aaaaaaaa}}", Kind: "PHONE", N: 1, Action: "warn"}}}
	w.trips.Pass("scope", "answered", true).Keep(w.store, warned)
	w.trips.Open("scope", "answered")
	for i, chunk := range []string{deltaEvent("hello"), stopLine} {
		if out := w.trips.Chunk("scope", "answered", i, []byte(chunk)); string(out) != chunk {
			t.Fatalf("chunk %d changed: %q", i, out)
		}
	}
	w.trips.Pass("scope", "unanswered", true).Keep(w.store, warned)
	w.trips.Complete("unanswered")
	got := w.records()
	if got[0].Restored == nil || len(got[0].Restored.Back) != 0 {
		t.Fatalf("answered: restored = %+v", got[0].Restored)
	}
	if got[1].Restored != nil {
		t.Fatalf("unanswered: restored = %+v", got[1].Restored)
	}
}

// A stream opened again starts over with nothing held, and the Round trip
// still counts all its response put back, once.
func TestAStreamOpenedAgainStartsOver(t *testing.T) {
	w := newWorld(t)
	placeholder := w.request("scope", "r1")
	w.trips.Open("scope", "r1")
	w.trips.Chunk("scope", "r1", 0, []byte(deltaEvent(placeholder)))
	if out := w.trips.Chunk("scope", "r1", 1, []byte(deltaEvent(placeholder[:7]))); len(out) != 0 {
		t.Fatalf("a Placeholder's start was not held: %q", out)
	}
	w.trips.Open("scope", "r1")
	out := w.trips.Chunk("scope", "r1", 0, []byte(deltaEvent(placeholder)))
	out = append(out, w.trips.Chunk("scope", "r1", 1, []byte(stopLine))...)
	if got := streamedText(t, string(out)); got != email {
		t.Fatalf("the second stream = %q", got)
	}
	if got := w.only().Restored; got == nil || got.Back[placeholder] != 2 {
		t.Fatalf("restored = %+v", got)
	}
}

// A connection that carries several requests in turn under one request ID
// makes a Round trip of each: the Host opens its stream once and goes on
// counting its chunks, and each request still gets its Held tail and its own
// record's count.
func TestRequestsInTurnOnOneRequestID(t *testing.T) {
	w := newWorld(t)
	index := 0
	var placeholder string
	for turn := 1; turn <= 3; turn++ {
		placeholder = w.request("scope", "session")
		w.trips.Pass("scope", "session", false)
		if turn == 1 {
			w.trips.Open("scope", "session")
		}
		var out []byte
		for _, chunk := range []string{deltaEvent("to "), deltaEvent(placeholder[:7]), deltaEvent(placeholder[7:]), stopLine, ""} {
			out = append(out, w.trips.Chunk("scope", "session", index, []byte(chunk))...)
			index++
		}
		if got := streamedText(t, string(out)); got != "to "+email {
			t.Fatalf("turn %d = %q", turn, got)
		}
	}
	w.trips.Complete("session")
	got := w.records()
	if len(got) != 3 {
		t.Fatalf("%d records", len(got))
	}
	for i, r := range got {
		if r.Restored == nil || r.Restored.Back[placeholder] != 1 {
			t.Fatalf("turn %d: restored = %+v", i+1, r.Restored)
		}
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

// A chunk out of its order, or one of a request the Trips do not know, is
// restored on its own and takes no place in a stream.
func TestAChunkOutOfOrderIsRestoredOnItsOwn(t *testing.T) {
	w := newWorld(t)
	placeholder := w.request("scope", "r1")
	w.trips.Open("scope", "r1")
	if out := w.trips.Chunk("scope", "r1", 5, []byte(deltaEvent(placeholder[:7]))); streamedText(t, string(out)) != placeholder[:7] {
		t.Fatalf("a chunk out of order was held: %q", out)
	}
	if out := w.trips.Chunk("scope", "unknown", 0, []byte(deltaEvent(placeholder))); streamedText(t, string(out)) != email {
		t.Fatalf("a chunk of an unknown request: %q", out)
	}
	out := w.trips.Chunk("scope", "r1", 0, []byte(deltaEvent(placeholder[:7])))
	out = append(out, w.trips.Chunk("scope", "r1", 1, []byte(deltaEvent(placeholder[7:])))...)
	out = append(out, w.trips.Chunk("scope", "r1", 2, []byte(stopLine))...)
	if got := streamedText(t, string(out)); got != email {
		t.Fatalf("the stream = %q", got)
	}
}

// A call that names no request belongs to no Round trip. Each Pass keeps a
// record of its own, the response is restored, a chunk on its own, and
// nothing is counted.
func TestACallThatNamesNoRequestIsRestoredAndNotCounted(t *testing.T) {
	w := newWorld(t)
	placeholder := w.request("scope", "")
	if w.trips.Pass("scope", "", false).Left(nil) {
		t.Fatal("a Pass of no Round trip found a body left")
	}
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
	w.trips.Complete("")
	if got := w.only().Restored; got != nil {
		t.Fatalf("counted: %+v", got)
	}
}

// Calls for one request from many goroutines leave one record, counted once.
func TestConcurrentCallsForOneRequest(t *testing.T) {
	w := newWorld(t)
	placeholder := w.request("scope", "r1")
	w.trips.Open("scope", "r1")
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for n := range 50 {
				w.trips.Chunk("scope", "r1", n, []byte(deltaEvent(placeholder)))
				w.trips.Pass("scope", "r1", false).Left([]byte("body"))
				if worker == 0 && n == 25 {
					w.trips.Complete("r1")
				}
			}
		})
	}
	wg.Wait()
	w.trips.Close()
	got := w.only().Restored
	if got == nil || got.Back[placeholder] == 0 {
		t.Fatalf("restored = %+v", got)
	}
	w.store.Flush()
	if again := w.only().Restored; again.Back[placeholder] != got.Back[placeholder] {
		t.Fatalf("counted again: %+v then %+v", got, again)
	}
}
