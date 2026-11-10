package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

// What a request's life looks like from the Host: its Passes, its response,
// and the one Masking record of them all.

const tripBody = `{"model":"m","stream":true,"input":"mail ` + seamEmail + `"}`

// tripRecords are the Masking records of h, the oldest first.
func tripRecords(t *testing.T, h *fakeHost) []records.Record {
	t.Helper()
	got := recordsOf(t, h.runtime.plugin)
	slices.Reverse(got)
	return got
}

// added is body as another plugin leaves it, having added text of its own.
func added(t *testing.T, body []byte, text string) []byte {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	fields["instructions"] = text
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Text another plugin adds between the Passes is masked by the later one, and
// what both found is one record, which the response counts into.
func TestTextAddedBetweenThePassesJoinsTheRequestsRecord(t *testing.T) {
	h := newFakeHost(t, hostV8)
	r := h.request("k", tripBody)
	h.pass(r, pluginabi.MethodRequestInterceptBefore)
	r.upstream = added(t, r.upstream, "memory: other@acme-corp.cn")
	h.pass(r, pluginabi.MethodRequestInterceptAfter)
	placeholders := emailPlaceholder.FindAllString(string(r.upstream), -1)
	if strings.Contains(string(r.upstream), "@acme-corp.cn") || len(placeholders) != 2 {
		t.Fatalf("the upstream gets %s", r.upstream)
	}
	h.respond(r, `{"output_text":"to `+placeholders[0]+` and `+placeholders[1]+`"}`)
	h.complete(r)
	got := tripRecords(t, h)
	if len(got) != 1 || got[0].N != 2 || len(got[0].Values) != 2 {
		t.Fatalf("records = %+v", got)
	}
	if back := got[0].Restored; back == nil || back.Back[placeholders[0]] != 1 || back.Back[placeholders[1]] != 1 {
		t.Fatalf("restored = %+v", back)
	}
}

// The Host hands a request over again for each credential it tries. However
// many it tries, and whatever is added each time, it is one request with one
// record, and each value in it once.
func TestEveryCredentialTriedIsTheSameRequest(t *testing.T) {
	h := newFakeHost(t, hostV8)
	r := h.request("k", tripBody)
	h.pass(r, pluginabi.MethodRequestInterceptBefore)
	masked := r.upstream
	for range 3 {
		r.upstream = added(t, masked, "memory: other@acme-corp.cn")
		h.pass(r, pluginabi.MethodRequestInterceptAfter)
		if strings.Contains(string(r.upstream), "@acme-corp.cn") {
			t.Fatalf("the upstream gets %s", r.upstream)
		}
	}
	h.respond(r, `{"output_text":"ok"}`)
	h.complete(r)
	if got := tripRecords(t, h); len(got) != 1 || got[0].N != 2 || len(got[0].Values) != 2 || got[0].Restored == nil {
		t.Fatalf("records = %+v", got)
	}
}

// A request sent again is another request: a value only warned about is
// logged and recorded each time it goes out, and once each time.
func TestARequestSentAgainIsWarnedAboutAndRecordedAgain(t *testing.T) {
	logs := capturePluginLogs(t)
	h := newFakeHost(t, hostV8, func(c *veilConfig) { c.Actions = map[string]string{"EMAIL": "warn"} })
	for range 3 {
		r := h.send("k", tripBody)
		if string(r.upstream) != tripBody {
			t.Fatalf("the upstream gets %s", r.upstream)
		}
		h.respond(r, `{"output_text":"ok"}`)
		h.complete(r)
	}
	if got := strings.Count(logs.String(), "veil let 1 value(s)"); got != 3 {
		t.Fatalf("warned %d times: %s", got, logs)
	}
	got := tripRecords(t, h)
	if len(got) != 3 {
		t.Fatalf("%d records", len(got))
	}
	for _, r := range got {
		if r.N != 1 || len(r.Values) != 1 || r.Values[0].Action != "warn" || r.Restored == nil {
			t.Fatalf("record = %+v", r)
		}
	}
}

// A streamed response that had nothing to restore still answers its request's
// record, as a whole response does.
func TestAStreamWithNothingToRestoreAnswersTheRecord(t *testing.T) {
	h := newFakeHost(t, hostV8, func(c *veilConfig) { c.Actions = map[string]string{"EMAIL": "warn"} })
	r := h.send("k", tripBody)
	var chunks []string
	for _, line := range responsesV8Lines("nothing to put back", 6) {
		chunks = append(chunks, line+"\n")
	}
	if got := deltas(t, h.stream(r, chunks)); got != "nothing to put back" {
		t.Fatalf("stream text = %q", got)
	}
	if got := tripRecords(t, h); len(got) != 1 || got[0].Restored == nil || len(got[0].Restored.Back) != 0 {
		t.Fatalf("records = %+v", got)
	}
	h.complete(r)
}

// A connection that carries several requests in turn, as Codex over a
// WebSocket does, has one request ID and one stream for all of them: the Host
// opens the stream once and goes on counting its chunks. Each turn is still
// restored, a Placeholder cut across chunks too, and has its own record.
func TestTurnsOnOneConnectionAreRestoredAndRecordedEach(t *testing.T) {
	h := newFakeHost(t, hostV8)
	r := h.request("k", tripBody)
	var s *fakeStream
	for turn := 1; turn <= 3; turn++ {
		if turn > 1 {
			body := added(t, []byte(tripBody), strings.Repeat("an earlier turn. ", turn))
			r = &fakeRequest{id: r.id, headers: r.headers, original: body, upstream: body}
		}
		if !h.pass(r, pluginabi.MethodRequestInterceptBefore) || !h.pass(r, pluginabi.MethodRequestInterceptAfter) {
			t.Fatalf("turn %d was refused: %+v", turn, r.rejected)
		}
		placeholder := emailPlaceholder.FindString(string(r.upstream))
		if strings.Contains(string(r.upstream), seamEmail) || placeholder == "" {
			t.Fatalf("turn %d: the upstream gets %s", turn, r.upstream)
		}
		if turn == 1 {
			s = h.open(r)
		}
		s.r, s.out = r, nil
		for _, line := range responsesV8Lines("to "+placeholder+" ok", 4) {
			s.send(line)
		}
		if text, _ := s.frames(); text != "to "+seamEmail+" ok" {
			t.Fatalf("turn %d: the client gets %q", turn, text)
		}
	}
	h.complete(r)
	got := tripRecords(t, h)
	if len(got) != 3 {
		t.Fatalf("%d records", len(got))
	}
	for i, record := range got {
		if record.N != 1 || record.Restored == nil || total(record.Restored.Back) != 1 {
			t.Fatalf("turn %d: record = %+v, restored %+v", i+1, record, record.Restored)
		}
	}
}

// The Host's word that a request is complete always gets an answer, since a
// failure would only be logged for every request, and it releases what Veil
// held for the request.
func TestRequestCompleteIsAlwaysAnswered(t *testing.T) {
	h := newFakeHost(t, hostV8)
	r := h.send("k", tripBody)
	placeholder := emailPlaceholder.FindString(string(r.upstream))
	h.complete(r)
	h.complete(&fakeRequest{id: "never seen"})
	if got := h.respond(r, `{"output_text":"`+placeholder+`"}`); !strings.Contains(got, seamEmail) {
		t.Fatalf("a late response was not restored: %s", got)
	}
	if got := tripRecords(t, h); len(got) != 1 || got[0].Restored != nil {
		t.Fatalf("a response after the request was complete counted: %+v", got)
	}
	h.runtime.close()
	h.complete(r)
	if h.callRaw(methodRequestComplete, []byte(`not json`)).OK != true {
		t.Fatal("a completion Veil could not read failed")
	}
}
