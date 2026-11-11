package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// openStream opens the stream of a request of its own, as CPA hands it over:
// the request's ID with every chunk, the request bodies with the header-init
// call only. Its Codex path hands over one SSE line per chunk with no line
// ending, the blank separator as an empty chunk no plugin rewrites, and what
// comes out is joined by the framer's line breaks, as frames reads it.
func openStream(t *testing.T, p *veilPlugin, scopeKey string, requestBody []byte) *fakeStream {
	t.Helper()
	return hostOf(t, p).open(&fakeRequest{id: newRequestID(), headers: bearer(scopeKey), original: requestBody, upstream: requestBody})
}

func deltaEvent(text string) []string {
	b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": text}})
	return []string{"event: content_block_delta\n", "data: " + string(b) + "\n", "\n"}
}

func streamedText(t *testing.T, stream string) string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(stream, "\n") {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev struct {
			Type  string `json:"type"`
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

func maskedPlaceholder(t testing.TB, p *veilPlugin, key string) string {
	t.Helper()
	body := intercept(t, p, abiRequestInterceptRequest{Headers: bearer(key), Body: []byte(`{"messages":[{"role":"user","content":"mail test@acme-corp.cn"}]}`)})
	placeholder := emailPlaceholder.FindString(string(body))
	if placeholder == "" {
		t.Fatalf("not masked: %s", body)
	}
	return placeholder
}

func TestStreamThroughTheHost(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	placeholder := maskedPlaceholder(t, p, "client-a")
	h := openStream(t, p, "client-a", []byte(`{"request":1}`))
	for _, piece := range []string{"sending to ", placeholder[:5], placeholder[5:12], placeholder[12:], " now"} {
		for _, line := range deltaEvent(piece) {
			h.send(line)
		}
	}
	for _, line := range []string{"event: message_stop\n", "data: {\"type\":\"message_stop\"}\n", "\n"} {
		h.send(line)
	}
	if got := streamedText(t, h.visible()); got != "sending to test@acme-corp.cn now" {
		t.Fatalf("client saw %q\n%s", got, h.visible())
	}
}

func TestStreamOfAnotherClientIsNotRestored(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	placeholder := maskedPlaceholder(t, p, "client-a")
	h := openStream(t, p, "client-b", []byte(`{"request":2}`))
	for _, line := range deltaEvent("leak " + placeholder) {
		h.send(line)
	}
	if !strings.Contains(h.visible(), placeholder) {
		t.Fatalf("another client's placeholder was restored:\n%s", h.visible())
	}
}

// frames checks every event reaches the client as an event line and a data
// line of its own and returns the restored text of the output deltas. Blank
// lines end an event; more than one in a row is no event (SSE ignores it).
func (s *fakeStream) frames() (string, int) {
	s.h.t.Helper()
	stream := strings.Join(s.out, "\n") + "\n\n"
	text, n := "", 0
	var frame []string
	for _, line := range strings.Split(stream, "\n") {
		if line != "" {
			frame = append(frame, line)
			continue
		}
		if len(frame) == 0 {
			continue
		}
		n++
		if len(frame) != 2 || !strings.HasPrefix(frame[0], "event: ") || !strings.HasPrefix(frame[1], "data: ") {
			s.h.t.Fatalf("frame %q is not an event line and a data line in\n%s", frame, stream)
		}
		var data struct {
			Type  string `json:"type"`
			Delta string `json:"delta"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(frame[1], "data: ")), &data); err != nil || "event: "+data.Type != frame[0] {
			s.h.t.Fatalf("frame %q: %v", frame, err)
		}
		text += data.Delta
		frame = nil
	}
	return text, n
}

func responsesV8Lines(text string, size int) []string {
	var lines []string
	add := func(typ string, body map[string]any) {
		body["type"] = typ
		b, _ := json.Marshal(body)
		lines = append(lines, "event: "+typ, "data: "+string(b), "")
	}
	add("response.created", map[string]any{"response": map[string]any{"id": "r1"}})
	for len(text) > 0 {
		n := min(size, len(text))
		add("response.output_text.delta", map[string]any{"item_id": "m1", "output_index": 0, "content_index": 0, "delta": text[:n]})
		text = text[n:]
	}
	add("response.completed", map[string]any{"response": map[string]any{"id": "r1"}})
	return lines
}

// The CPA v8 failure: once a caller had a value masked, its Responses streams
// with event lines reached the client as "event: xdata: {...}", and the host
// closed them before the first payload.
func TestV8ResponsesStreamsKeepTheirEventLines(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	placeholder := maskedPlaceholder(t, p, "k")
	body := []byte(`{"input":"later"}`)

	s := openStream(t, p, "k", body)
	for _, line := range responsesV8Lines("to "+placeholder+" ok", 4) {
		s.send(line)
	}
	if text, n := s.frames(); text != "to test@acme-corp.cn ok" || n < 3 {
		t.Fatalf("text %q in %d frames", text, n)
	}

	// Plain text from the same caller, which failed the same way.
	s = openStream(t, p, "k", []byte(`{"input":"hello"}`))
	for _, line := range responsesV8Lines("OK", 4) {
		s.send(line)
	}
	if text, _ := s.frames(); text != "OK" {
		t.Fatalf("plain text %q", text)
	}
}

// A stream is known by its request's ID: it holds Placeholders cut across
// chunks, and two identical requests at once are two streams, each holding.
func TestStreamsKnownByRequestID(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	placeholder := maskedPlaceholder(t, p, "k")
	body := []byte(`{"input":"same"}`)
	lines := responsesV8Lines("to "+placeholder+" ok", 4)
	a := openStream(t, p, "k", body)
	b := openStream(t, p, "k", body)
	for i := range lines {
		a.send(lines[i])
		b.send(lines[i])
	}
	for name, s := range map[string]*fakeStream{"first": a, "second": b} {
		if text, _ := s.frames(); text != "to test@acme-corp.cn ok" {
			t.Fatalf("%s stream text %q", name, text)
		}
	}
}

// A chunk that names no request has no stream to join. It is restored on its
// own: a whole Placeholder comes back, and one cut across chunks does not.
func TestAChunkWithoutARequestIDIsRestoredOnItsOwn(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	placeholder := maskedPlaceholder(t, p, "k")
	for size, want := range map[int]string{len(placeholder) + 3: "to test@acme-corp.cn", 7: "to " + placeholder} {
		s := hostOf(t, p).open(&fakeRequest{headers: bearer("k")})
		for _, line := range responsesV8Lines("to "+placeholder, size) {
			s.send(line)
		}
		if text, _ := s.frames(); text != want {
			t.Fatalf("in pieces of %d: text %q, want %q", size, text, want)
		}
	}
}

// The host offers its schema at plugin.register; Veil takes 5 where the
// host has it, so payload chunks come without the bodies, and the original
// one on a Host that does not, whose requests it stops.
func TestRegisterTakesTheHostsSchema(t *testing.T) {
	runtime := &pluginRuntime{}
	defer runtime.close()
	dir := t.TempDir()
	for host, want := range map[uint32]uint32{0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 5, 10: 5} {
		raw, err := json.Marshal(abiLifecycleRequest{PluginDir: dir, SchemaVersion: host})
		if err != nil {
			t.Fatal(err)
		}
		out, err := seamCall(context.Background(), runtime, pluginabi.MethodPluginRegister, raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := decodeRegistration(t, out).SchemaVersion; got != want {
			t.Errorf("host schema %d: registered with %d, want %d", host, got, want)
		}
	}
}

// A chunk as CPA encodes it for a plugin of schema 5, without the bodies,
// finds its stream by the RequestID field.
func TestStreamChunkEnvelopeCarriesTheRequestID(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	placeholder := maskedPlaceholder(t, p, "k")
	runtime := &pluginRuntime{}
	defer runtime.close()
	runtime.plugin = p
	headers := map[string][]string{"Authorization": {"Bearer k"}}
	s := &fakeStream{h: &fakeHost{t: t}}
	for i, line := range append([]string{""}, responsesV8Lines("to "+placeholder+" ok", 4)...) {
		req := map[string]any{"RequestID": "r1", "RequestHeaders": headers, "Body": []byte(line), "ChunkIndex": i - 1}
		if i == 0 {
			req["RequestBody"] = []byte(`{"input":"x"}`)
		}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		out, err := seamCall(context.Background(), runtime, pluginabi.MethodResponseInterceptStreamChunk, raw)
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			OK     bool                                   `json:"ok"`
			Result pluginapi.StreamChunkInterceptResponse `json:"result"`
		}
		if err := json.Unmarshal(out, &env); err != nil || !env.OK {
			t.Fatalf("envelope %s: %v", out, err)
		}
		switch {
		case i == 0, env.Result.DropChunk:
		case len(env.Result.Body) > 0:
			s.out = append(s.out, string(env.Result.Body))
		default:
			s.out = append(s.out, line)
		}
	}
	if text, _ := s.frames(); text != "to test@acme-corp.cn ok" {
		t.Fatalf("text %q", text)
	}
}

// BenchmarkLongHistoryStream is what one stream of 106 chunks of a request
// with an agent's 3.7 MB history costs Veil through the ABI: the request
// bodies come with the header-init call only, and the chunks are known by the
// request's ID.
func BenchmarkLongHistoryStream(b *testing.B) {
	p := newConfiguredInterceptor(b, "")
	maskedPlaceholder(b, p, "k")
	runtime := &pluginRuntime{}
	defer runtime.close()
	runtime.plugin = p
	history := []byte(`{"input":"` + strings.Repeat("an old turn of the conversation, ", 112_000) + `"}`)
	lines := responsesV8Lines(strings.Repeat("summary ", 34), 8)
	headers := map[string][]string{"Authorization": {"Bearer k"}}
	envelopes := make([][]byte, 0, len(lines)+1)
	for i, line := range append([]string{""}, lines...) {
		req := map[string]any{"RequestID": "r1", "RequestHeaders": headers, "Body": []byte(line), "ChunkIndex": i - 1}
		if i == 0 {
			req["OriginalRequest"], req["RequestBody"] = history, history
		}
		raw, err := json.Marshal(req)
		if err != nil {
			b.Fatal(err)
		}
		envelopes = append(envelopes, raw)
	}
	b.ResetTimer()
	for range b.N {
		for _, raw := range envelopes {
			if _, err := seamCall(context.Background(), runtime, pluginabi.MethodResponseInterceptStreamChunk, raw); err != nil {
				b.Fatal(err)
			}
		}
	}
}
