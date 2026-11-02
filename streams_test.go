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
