package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// hostStream delivers chunks through the plugin as the host does: one
// header-only call, then each chunk by index, replacing it with a non-empty
// Body and skipping it on DropChunk.
type hostStream struct {
	t       *testing.T
	plugin  *veilPlugin
	req     pluginapi.StreamChunkInterceptRequest
	next    int
	visible strings.Builder
}

func openStream(t *testing.T, p *veilPlugin, scopeKey string, requestBody []byte) *hostStream {
	t.Helper()
	h := &hostStream{t: t, plugin: p, req: pluginapi.StreamChunkInterceptRequest{RequestHeaders: bearer(scopeKey), RequestBody: requestBody}}
	h.req.ChunkIndex = pluginapi.StreamChunkHeaderInitIndex
	if _, err := p.InterceptStreamChunk(nil, h.req); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *hostStream) send(chunk string) {
	h.t.Helper()
	req := h.req
	req.Body = []byte(chunk)
	req.ChunkIndex = h.next
	h.next++
	resp, err := h.plugin.InterceptStreamChunk(nil, req)
	if err != nil {
		h.t.Fatal(err)
	}
	switch {
	case resp.DropChunk:
	case len(resp.Body) > 0:
		h.visible.Write(resp.Body)
	default:
		h.visible.WriteString(chunk)
	}
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

func maskedPlaceholder(t *testing.T, p *veilPlugin, key string) string {
	t.Helper()
	body := intercept(t, p, pluginapi.RequestInterceptRequest{Headers: bearer(key), Body: []byte(`{"messages":[{"role":"user","content":"mail test@acme-corp.cn"}]}`)})
	placeholder := emailPlaceholder.FindString(string(body))
	if placeholder == "" {
		t.Fatalf("not masked: %s", body)
	}
	return placeholder
}

func TestStreamThroughTheHost(t *testing.T) {
	p := newConfiguredInterceptor(t, "").(*veilPlugin)
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
	if got := streamedText(t, h.visible.String()); got != "sending to test@acme-corp.cn now" {
		t.Fatalf("client saw %q\n%s", got, h.visible.String())
	}
	if len(p.streams.streams) != 0 {
		t.Fatal("finished stream was not forgotten")
	}
}

// Two streams of the same client and body cannot be told apart chunk by
// chunk; neither holds, so neither mixes the other's text into its own.
func TestConcurrentIdenticalStreams(t *testing.T) {
	p := newConfiguredInterceptor(t, "").(*veilPlugin)
	placeholder := maskedPlaceholder(t, p, "client-a")
	body := []byte(`{"same":true}`)
	a := openStream(t, p, "client-a", body)
	b := openStream(t, p, "client-a", body)
	for _, piece := range []string{"a: ", placeholder, " end"} {
		for _, line := range deltaEvent(piece) {
			a.send(line)
		}
	}
	for _, piece := range []string{"b: ", placeholder, " end"} {
		for _, line := range deltaEvent(piece) {
			b.send(line)
		}
	}
	if got := streamedText(t, a.visible.String()); got != "a: test@acme-corp.cn end" {
		t.Fatalf("a saw %q", got)
	}
	if got := streamedText(t, b.visible.String()); got != "b: test@acme-corp.cn end" {
		t.Fatalf("b saw %q", got)
	}
}

func TestStreamOfAnotherClientIsNotRestored(t *testing.T) {
	p := newConfiguredInterceptor(t, "").(*veilPlugin)
	placeholder := maskedPlaceholder(t, p, "client-a")
	h := openStream(t, p, "client-b", []byte(`{"request":2}`))
	for _, line := range deltaEvent("leak " + placeholder) {
		h.send(line)
	}
	if !strings.Contains(h.visible.String(), placeholder) {
		t.Fatalf("another client's placeholder was restored:\n%s", h.visible.String())
	}
}

// v8Stream delivers a Responses stream as CPA v8's Codex path does: one SSE
// line per chunk with no line ending, the blank separator as an empty chunk
// no plugin rewrites, and what comes out joined by the framer's line breaks.
type v8Stream struct {
	t      *testing.T
	plugin *veilPlugin
	req    pluginapi.StreamChunkInterceptRequest
	next   int
	out    []string
}

func openV8Stream(t *testing.T, p *veilPlugin, scopeKey string, requestBody []byte) *v8Stream {
	t.Helper()
	s := &v8Stream{t: t, plugin: p, req: pluginapi.StreamChunkInterceptRequest{RequestHeaders: bearer(scopeKey), OriginalRequest: requestBody, RequestBody: requestBody}}
	s.req.ChunkIndex = pluginapi.StreamChunkHeaderInitIndex
	if _, err := p.InterceptStreamChunk(nil, s.req); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *v8Stream) send(line string) {
	s.t.Helper()
	req := s.req
	req.Body = []byte(line)
	req.ChunkIndex = s.next
	s.next++
	resp, err := s.plugin.InterceptStreamChunk(nil, req)
	if err != nil {
		s.t.Fatal(err)
	}
	switch {
	case resp.DropChunk:
	case len(resp.Body) > 0:
		s.out = append(s.out, string(resp.Body))
	default:
		s.out = append(s.out, line)
	}
}

// frames checks every event reaches the client as an event line and a data
// line of its own and returns the restored text of the output deltas. Blank
// lines end an event; more than one in a row is no event (SSE ignores it).
func (s *v8Stream) frames() (string, int) {
	s.t.Helper()
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
			s.t.Fatalf("frame %q is not an event line and a data line in\n%s", frame, stream)
		}
		var data struct {
			Type  string `json:"type"`
			Delta string `json:"delta"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(frame[1], "data: ")), &data); err != nil || "event: "+data.Type != frame[0] {
			s.t.Fatalf("frame %q: %v", frame, err)
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
	p := newConfiguredInterceptor(t, "").(*veilPlugin)
	placeholder := maskedPlaceholder(t, p, "k")
	body := []byte(`{"input":"later"}`)

	s := openV8Stream(t, p, "k", body)
	for _, line := range responsesV8Lines("to "+placeholder+" ok", 4) {
		s.send(line)
	}
	if text, n := s.frames(); text != "to test@acme-corp.cn ok" || n < 3 {
		t.Fatalf("text %q in %d frames", text, n)
	}

	// Plain text from the same caller, which failed the same way.
	s = openV8Stream(t, p, "k", []byte(`{"input":"hello"}`))
	for _, line := range responsesV8Lines("OK", 4) {
		s.send(line)
	}
	if text, _ := s.frames(); text != "OK" {
		t.Fatalf("plain text %q", text)
	}
}

// Two streams of one request at once stop holding, so neither can join a
// Placeholder cut in two (a limit of a host that gives no stream ID); an
// event line held when holding stops still goes out on a line of its own,
// and whole Placeholders still restore.
func TestV8ConcurrentStreamsKeepTheirEventLines(t *testing.T) {
	p := newConfiguredInterceptor(t, "").(*veilPlugin)
	placeholder := maskedPlaceholder(t, p, "k")
	body := []byte(`{"input":"same"}`)
	a := openV8Stream(t, p, "k", body)
	lines := responsesV8Lines("to "+placeholder, len(placeholder)+3)
	a.send(lines[0])
	b := openV8Stream(t, p, "k", body) // the same request again: holding stops
	for _, line := range lines[1:] {
		a.send(line)
	}
	for _, line := range lines {
		b.send(line)
	}
	for name, s := range map[string]*v8Stream{"first": a, "second": b} {
		if text, _ := s.frames(); text != "to test@acme-corp.cn" {
			t.Fatalf("%s stream text %q", name, text)
		}
	}
}
