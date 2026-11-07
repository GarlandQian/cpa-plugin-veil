package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	seamEmail = "test@acme-corp.cn"
	seamBody  = `{"model":"m","stream":true,"input":"mail ` + seamEmail + `"}`
)

// The guarantee of ADR-0002 at the place the Host calls: however a request
// hook goes, the original text does not reach the upstream.
func TestRequestHooksNeverLetTheOriginalThrough(t *testing.T) {
	readable := []byte(`{"Model":"m","Headers":{"Authorization":["Bearer k"]},"Body":"` + base64.StdEncoding.EncodeToString([]byte(seamBody)) + `"}`)
	wrongType := []byte(`{"Model":13800138000,"Body":"` + base64.StdEncoding.EncodeToString([]byte(seamBody)) + `"}`)
	const stopped = `{"model":"m","stream":true,"input":[]}`
	for name, tt := range map[string]struct {
		state func(*fakeHost)
		call  []byte
		want  string
	}{
		"no runtime":             {func(h *fakeHost) { h.runtime = nil }, readable, stopped},
		"not registered":         {func(h *fakeHost) { h.runtime = &pluginRuntime{} }, readable, stopped},
		"shut down":              {func(h *fakeHost) { h.runtime.close() }, readable, stopped},
		"a field of a new type":  {nil, wrongType, "{}"},
		"not JSON":               {nil, []byte(`not json`), "{}"},
		"cut short":              {nil, readable[:20], "{}"},
		"the body renamed":       {nil, []byte(strings.Replace(string(readable), `"Body"`, `"Payload"`, 1)), "{}"},
		"too large to be copied": {nil, nil, "{}"},
		"no runtime, unreadable": {func(h *fakeHost) { h.runtime = nil }, wrongType, "{}"},
		"shut down, unreadable":  {func(h *fakeHost) { h.runtime.close() }, []byte(`not json`), "{}"},
	} {
		for _, profile := range hostProfiles {
			for _, method := range []string{pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter} {
				t.Run(name+"/"+profile.name+"/"+method, func(t *testing.T) {
					h := newFakeHost(t, profile)
					if tt.state != nil {
						tt.state(h)
					}
					if got := h.acted(h.callRaw(method, tt.call), []byte(seamBody)); string(got) != tt.want {
						t.Fatalf("the upstream gets %s, want %s", got, tt.want)
					}
				})
			}
		}
	}
}

// A request with no body has nothing to keep from the upstream, and stays as
// the Host has it.
func TestARequestHookLeavesAnEmptyBodyAlone(t *testing.T) {
	h := newFakeHost(t, hostV8)
	h.runtime.close()
	if got := h.acted(h.callRaw(pluginabi.MethodRequestInterceptBefore, []byte(`{"Model":"m","Body":null}`)), nil); got != nil {
		t.Fatalf("the upstream gets %s", got)
	}
}

// A response or a chunk Veil cannot restore goes on with its Placeholders:
// nothing original goes anywhere it should not.
func TestOtherHooksStillFailAsTheyWere(t *testing.T) {
	h := newFakeHost(t, hostV8)
	r := h.send("k", seamBody)
	placeholder := emailPlaceholder.FindString(string(r.upstream))
	h.runtime.close()
	if got := h.respond(r, placeholder); got != placeholder {
		t.Fatalf("response = %q", got)
	}
	if got := h.stream(r, []string{placeholder}); got != placeholder {
		t.Fatalf("stream = %q", got)
	}
	if h.call(pluginabi.MethodManagementHandle, map[string]any{}).OK {
		t.Fatal("a management call of a closed runtime succeeded")
	}
}

// A Host that hands Veil calls it cannot read must be easy to tell from a
// silent outage: the log says what failed, the records page shows the request,
// and neither quotes the call.
func TestAnUnreadableCallIsLoggedAndRecorded(t *testing.T) {
	logs := capturePluginLogs(t)
	h := newFakeHost(t, hostV8)
	h.callRaw(pluginabi.MethodRequestInterceptBefore, []byte(`{"Model":13800138000,"Body":"`+base64.StdEncoding.EncodeToString([]byte(seamBody))+`"}`))
	for _, want := range []string{"veil stopped a request", pluginabi.MethodRequestInterceptBefore, `"Model"`} {
		if !strings.Contains(strings.ReplaceAll(logs.String(), `\"`, `"`), want) {
			t.Errorf("the log lacks %s: %s", want, logs)
		}
	}
	if strings.Contains(logs.String(), "13800138000") || strings.Contains(logs.String(), seamEmail) {
		t.Fatalf("the log quotes the call: %s", logs)
	}
	h.runtime.plugin.records.Flush()
	var resp pluginapi.ManagementResponse
	if !h.result(h.call(pluginabi.MethodManagementHandle, map[string]any{"Method": http.MethodGet, "Path": "/v0/management/plugins/veil/records"}), &resp) {
		t.Fatal("the records could not be read")
	}
	var list struct {
		Records []struct {
			Stopped string `json:"stopped"`
		} `json:"records"`
	}
	if err := json.Unmarshal(resp.Body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Records) != 1 || list.Records[0].Stopped != "error" {
		t.Fatalf("records = %s", resp.Body)
	}
}

// With nothing running there is no record to keep, and the log still says why.
func TestAStoppedRequestWithNoInstanceIsLogged(t *testing.T) {
	logs := capturePluginLogs(t)
	h := newFakeHost(t, hostV8)
	h.runtime.close()
	h.send("k", seamBody)
	if !strings.Contains(logs.String(), "shutting down") {
		t.Fatalf("log = %s", logs)
	}
}

// Veil reads a few fields of what the Host sends. A Host release changing any
// other cannot fail a call, which would now stop every request.
func TestFieldsVeilDoesNotReadCannotFailACall(t *testing.T) {
	h := newFakeHost(t, hostV8)
	call := map[string]any{
		"Metadata": "no longer an object", "ToFormat": 7, "Stream": "yes", "TraceID": []int{1}, "CallerScope": map[string]any{"a": 1},
		"Headers": bearer("k"), "Body": []byte(seamBody),
	}
	got := h.acted(h.call(pluginabi.MethodRequestInterceptBefore, call), []byte(seamBody))
	if strings.Contains(string(got), seamEmail) || !emailPlaceholder.Match(got) {
		t.Fatalf("the upstream gets %s", got)
	}
	chunk := map[string]any{"Metadata": 1, "HistoryChunks": "gone", "ResponseHeaders": 2, "RequestHeaders": bearer("k"), "Body": []byte("hello"), "ChunkIndex": 0}
	if !h.call(pluginabi.MethodResponseInterceptStreamChunk, chunk).OK {
		t.Fatal("a chunk failed on a field Veil does not read")
	}
}

// A request masks and comes back restored on either Host, whole and streamed
// in pieces that cut a Placeholder apart.
func TestRoundTripAtTheHostSeam(t *testing.T) {
	for _, tt := range []struct {
		profile hostProfile
		schema  uint32
	}{{hostV7, 1}, {hostV8, veilSchemaVersion}} {
		t.Run(tt.profile.name, func(t *testing.T) {
			h := newFakeHost(t, tt.profile)
			if h.schema != tt.schema {
				t.Fatalf("registered with schema %d, want %d", h.schema, tt.schema)
			}
			r := h.send("k", seamBody)
			if strings.Contains(string(r.upstream), seamEmail) {
				t.Fatalf("the upstream gets %s", r.upstream)
			}
			placeholder := emailPlaceholder.FindString(string(r.upstream))
			if got := h.respond(r, `{"output_text":"to `+placeholder+`"}`); got != `{"output_text":"to `+seamEmail+`"}` {
				t.Fatalf("response = %s", got)
			}
			var chunks []string
			for _, line := range responsesV8Lines("to "+placeholder+" ok", 4) {
				chunks = append(chunks, line+"\n")
			}
			if got := deltas(t, h.stream(h.send("k", seamBody), chunks)); got != "to "+seamEmail+" ok" {
				t.Fatalf("stream text = %q", got)
			}
		})
	}
}

// deltas joins the text of a Responses stream's deltas.
func deltas(t *testing.T, stream string) string {
	t.Helper()
	var text strings.Builder
	for _, line := range strings.Split(stream, "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var event struct {
			Delta string `json:"delta"`
		}
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Fatalf("%q: %v", payload, err)
		}
		text.WriteString(event.Delta)
	}
	return text.String()
}
