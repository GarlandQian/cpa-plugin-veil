package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
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
		for _, profile := range []hostProfile{hostV7, hostV8} {
			for _, method := range []string{pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter} {
				t.Run(name+"/"+profile.name+"/"+method, func(t *testing.T) {
					h := newFakeHost(t, profile)
					if tt.state != nil {
						tt.state(h)
					}
					got, rejected := h.acted(h.callRaw(method, tt.call), []byte(seamBody))
					if string(got) != tt.want {
						t.Fatalf("the body the Host goes on with is %s, want %s", got, tt.want)
					}
					if (rejected != nil) != (profile.schema > 0) {
						t.Fatalf("refused: %+v", rejected)
					}
					if rejected != nil && strings.Contains(string(rejected.ResponseBody), seamEmail) {
						t.Fatalf("the client is told %s", rejected.ResponseBody)
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
	if got, rejected := h.acted(h.callRaw(pluginabi.MethodRequestInterceptBefore, []byte(`{"Model":"m","Body":null}`)), nil); got != nil || rejected != nil {
		t.Fatalf("the upstream gets %s, refused: %+v", got, rejected)
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
	got, rejected := h.acted(h.call(pluginabi.MethodRequestInterceptBefore, call), []byte(seamBody))
	if strings.Contains(string(got), seamEmail) || !emailPlaceholder.Match(got) || rejected != nil {
		t.Fatalf("the upstream gets %s, refused: %+v", got, rejected)
	}
	chunk := map[string]any{"Metadata": 1, "HistoryChunks": "gone", "ResponseHeaders": 2, "RequestHeaders": bearer("k"), "Body": []byte("hello"), "ChunkIndex": 0}
	if !h.call(pluginabi.MethodResponseInterceptStreamChunk, chunk).OK {
		t.Fatal("a chunk failed on a field Veil does not read")
	}
}

// A Stopped request never reaches the upstream, and the client gets a refusal
// it can read.
func TestAStoppedRequestIsRefused(t *testing.T) {
	block := func(c *veilConfig) { c.Actions = map[string]string{"EMAIL": "block"} }
	r := newFakeHost(t, hostV8, block).send("k", seamBody)
	if r.upstream != nil || r.rejected == nil || r.rejected.StatusCode != http.StatusForbidden {
		t.Fatalf("the upstream gets %s, refused: %+v", r.upstream, r.rejected)
	}
	if got := r.rejected.ResponseHeaders.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
}

// A Host older than CPA v8 still gets Veil registered, and every request of
// it stopped: one that failed to register would run with no Veil, and send
// every request as it came. The log says what to do about it, once at
// registration and for each request, which is recorded once.
func TestAHostOlderThanV8HasEveryRequestStopped(t *testing.T) {
	const clean = `{"model":"m","stream":true,"input":"hello"}`
	const stopped = `{"model":"m","stream":true,"input":[]}`
	for _, tt := range []struct {
		profile hostProfile
		offers  string
	}{
		{hostV7, "no plugin schema"},
		{hostProfile{name: "schema 4", schema: 4}, "plugin schema 4"},
	} {
		t.Run(tt.profile.name, func(t *testing.T) {
			logs := capturePluginLogs(t)
			h := newFakeHost(t, tt.profile, func(c *veilConfig) { c.SkipModels = []string{"m"} })
			if h.schema != originalSchemaVersion {
				t.Fatalf("registered with schema %d", h.schema)
			}
			if !strings.Contains(logs.String(), "veil will stop every request") || !strings.Contains(logs.String(), tt.offers) {
				t.Fatalf("registration log = %s", logs)
			}
			logs.Reset()
			for _, body := range []string{seamBody, clean} {
				r := h.send("k", body)
				switch {
				case tt.profile.schema == 0 && (string(r.upstream) != stopped || r.rejected != nil):
					t.Fatalf("the upstream gets %s, refused: %+v", r.upstream, r.rejected)
				case tt.profile.schema > 0 && (r.upstream != nil || r.rejected == nil || !strings.Contains(string(r.rejected.ResponseBody), "Veil needs CLIProxyAPI v8")):
					t.Fatalf("the upstream gets %s, refused: %+v", r.upstream, r.rejected)
				}
			}
			if got := strings.Count(logs.String(), "veil stopped a request"); got != 2 || !strings.Contains(logs.String(), "upgrade CLIProxyAPI") {
				t.Fatalf("%d stops logged: %s", got, logs)
			}
			if got := recordsOf(t, h.runtime.plugin); len(got) != 2 || got[0].Stopped != records.StoppedError {
				t.Fatalf("records = %+v", got)
			}
		})
	}
}

// The client gets the error its protocol has, saying which Kinds stopped the
// request and nothing of the values or where they were.
func TestAStoppedRequestTellsTheClientInItsProtocol(t *testing.T) {
	h := newFakeHost(t, hostV8, func(c *veilConfig) { c.Actions = map[string]string{"EMAIL": "block", "PHONE": "block"} })
	const body = `{"input":"mail ` + seamEmail + ` or 13800138000"}`
	for _, tt := range []struct {
		format, field, want string // the field of error that marks the shape
	}{
		{"openai", "code", "veil_stopped"},
		{"openai-response", "code", "veil_stopped"},
		{"", "code", "veil_stopped"},
		{"claude", "type", "permission_error"},
		{"gemini", "status", "PERMISSION_DENIED"},
		{"gemini-cli", "status", "PERMISSION_DENIED"},
	} {
		t.Run(tt.format, func(t *testing.T) {
			_, rejected := h.acted(h.call(pluginabi.MethodRequestInterceptBefore, map[string]any{"SourceFormat": tt.format, "Headers": bearer("k"), "Body": []byte(body)}), []byte(body))
			if rejected == nil {
				t.Fatal("not refused")
			}
			var decoded struct {
				Error map[string]any `json:"error"`
			}
			if err := json.Unmarshal(rejected.ResponseBody, &decoded); err != nil {
				t.Fatalf("%s: %v", rejected.ResponseBody, err)
			}
			if decoded.Error[tt.field] != tt.want {
				t.Fatalf("not the %q shape: %s", tt.format, rejected.ResponseBody)
			}
			if told, _ := decoded.Error["message"].(string); !strings.Contains(told, "EMAIL, PHONE") {
				t.Fatalf("told %q", told)
			}
			for _, secret := range []string{seamEmail, "13800138000", "input"} {
				if strings.Contains(string(rejected.ResponseBody), secret) {
					t.Fatalf("the client is told %s", rejected.ResponseBody)
				}
			}
		})
	}
}

// A request Veil could not handle says only that: the reason is for the log.
func TestAFailedRequestToldNothingOfWhy(t *testing.T) {
	logs := capturePluginLogs(t)
	h := newFakeHost(t, hostV8)
	_, rejected := h.acted(h.callRaw(pluginabi.MethodRequestInterceptBefore, []byte(`{"Model":13800138000}`)), []byte(seamBody))
	if rejected == nil || !strings.Contains(string(rejected.ResponseBody), "See the CLIProxyAPI log") || strings.Contains(string(rejected.ResponseBody), "Model") {
		t.Fatalf("refused: %+v", rejected)
	}
	if !strings.Contains(logs.String(), "Model") {
		t.Fatalf("log = %s", logs)
	}
}

// A request masks and comes back restored, whole and streamed in pieces that
// cut a Placeholder apart.
func TestRoundTripAtTheHostSeam(t *testing.T) {
	h := newFakeHost(t, hostV8)
	if h.schema != veilSchemaVersion {
		t.Fatalf("registered with schema %d, want %d", h.schema, veilSchemaVersion)
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
