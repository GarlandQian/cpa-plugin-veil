package restore

import (
	"encoding/json"
	"strings"
	"testing"
)

// feed runs chunks through a Stream and returns everything delivered.
func feed(t *testing.T, s *Stream, chunks []string) string {
	t.Helper()
	var out strings.Builder
	for _, c := range chunks {
		got, _ := s.Chunk([]byte(c))
		out.Write(got)
	}
	return out.String()
}

// events splits an SSE stream into its events' data payloads, in order.
func events(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, block := range strings.Split(strings.ReplaceAll(stream, "\r\n", "\n"), "\n\n") {
		for _, line := range strings.Split(block, "\n") {
			payload, ok := strings.CutPrefix(line, "data:")
			if !ok {
				continue
			}
			payload = strings.TrimSpace(payload)
			if payload == "[DONE]" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(payload), &m); err != nil {
				t.Fatalf("event data is not JSON: %q in\n%s", payload, stream)
			}
			out = append(out, m)
		}
	}
	return out
}

func dig(m any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			obj, _ := m.(map[string]any)
			m = obj[k]
		case int:
			list, _ := m.([]any)
			if k >= len(list) {
				return nil
			}
			m = list[k]
		}
	}
	return m
}

func claudeEvent(name, data string) []string {
	return []string{"event: " + name + "\n", "data: " + data + "\n", "\n"}
}

func textDelta(text string) string {
	b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": text}})
	return string(b)
}

// split cuts s into pieces of at most n bytes, as a model streams tokens.
func split(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func claudeText(t *testing.T, stream string) string {
	var b strings.Builder
	for _, ev := range events(t, stream) {
		if ev["type"] == "content_block_delta" {
			if s, ok := dig(ev, "delta", "text").(string); ok {
				b.WriteString(s)
			}
		}
	}
	return b.String()
}

func TestStreamClaudeLinePerChunk(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	text := "I will mail " + p + " and " + strings.ToLower(p) + " now {ok}"
	for _, size := range []int{1, 2, 3, 5, 7, 11} {
		var chunks []string
		chunks = append(chunks, claudeEvent("message_start", `{"type":"message_start","message":{"id":"m","content":[]}}`)...)
		for i, piece := range split(text, size) {
			chunks = append(chunks, claudeEvent("content_block_delta", textDelta(piece))...)
			if i == 2 {
				chunks = append(chunks, claudeEvent("ping", `{"type":"ping"}`)...)
			}
		}
		chunks = append(chunks, claudeEvent("content_block_stop", `{"type":"content_block_stop","index":0}`)...)
		chunks = append(chunks, claudeEvent("message_stop", `{"type":"message_stop"}`)...)
		out := feed(t, r.NewStream("", true), chunks)
		if got := claudeText(t, out); got != "I will mail a@b.com and a@b.com now {ok}" {
			t.Fatalf("size %d: text = %q\n%s", size, got, out)
		}
		if strings.Count(out, "event: content_block_stop") != 1 || !strings.HasSuffix(out, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n") {
			t.Fatalf("size %d: framing broken:\n%s", size, out)
		}
		// Control: without holding, a placeholder cut in pieces is not
		// restored, so the test above exercises the Held tail.
		if got := claudeText(t, feed(t, r.NewStream("", false), chunks)); strings.Contains(got, "a@b.com") {
			t.Fatalf("size %d: restored without holding: %q", size, got)
		}
	}
}

func TestStreamClaudeEventPerChunk(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "PHONE", "13800138000")
	var chunks []string
	for _, piece := range split("call "+p+" please", 4) {
		chunks = append(chunks, "event: content_block_delta\ndata: "+textDelta(piece)+"\n\n")
	}
	chunks = append(chunks, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	out := feed(t, r.NewStream("", true), chunks)
	if got := claudeText(t, out); got != "call 13800138000 please" {
		t.Fatalf("text = %q\n%s", got, out)
	}
}

func TestStreamReleasesAnUnfinishedTail(t *testing.T) {
	r, v := newRestorer(t)
	v.Placeholder("", "EMAIL", "a@b.com")
	chunks := claudeEvent("content_block_delta", textDelta("ends with {{EMA"))
	chunks = append(chunks, claudeEvent("content_block_stop", `{"type":"content_block_stop","index":0}`)...)
	out := feed(t, r.NewStream("", true), chunks)
	if got := claudeText(t, out); got != "ends with {{EMA" {
		t.Fatalf("text = %q\n%s", got, out)
	}
	if strings.Index(out, "{{EMA") > strings.Index(out, "content_block_stop") {
		t.Fatalf("held text came after the block ended:\n%s", out)
	}
}

func TestStreamLeavesThinkingAlone(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	data := `{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"` + p + `"}}`
	out := feed(t, r.NewStream("", true), claudeEvent("content_block_delta", data))
	if !strings.Contains(out, p) {
		t.Fatalf("thinking was restored:\n%s", out)
	}
}

func TestStreamClaudeToolInput(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "SECRET", `pa"ss`)
	args := `{"password": "` + p + `"}`
	var chunks []string
	for _, piece := range split(args, 3) {
		b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 1, "delta": map[string]any{"type": "input_json_delta", "partial_json": piece}})
		chunks = append(chunks, claudeEvent("content_block_delta", string(b))...)
	}
	chunks = append(chunks, claudeEvent("content_block_stop", `{"type":"content_block_stop","index":1}`)...)
	out := feed(t, r.NewStream("", true), chunks)
	var b strings.Builder
	for _, ev := range events(t, out) {
		if s, ok := dig(ev, "delta", "partial_json").(string); ok {
			b.WriteString(s)
		}
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(b.String()), &parsed); err != nil || parsed["password"] != `pa"ss` {
		t.Fatalf("arguments = %q (%v)", b.String(), err)
	}
}

func TestStreamOpenAIChat(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	q := v.Placeholder("", "SECRET", `back\slash`)
	var chunks []string
	for _, piece := range split("mail "+p, 3) {
		b, _ := json.Marshal(map[string]any{"id": "c", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": piece}}}})
		chunks = append(chunks, "data: "+string(b)+"\n\n")
	}
	for call, args := range []string{`{"to":"` + p + `"}`, `{"key":"` + q + `"}`} {
		for _, piece := range split(args, 4) {
			b, _ := json.Marshal(map[string]any{"id": "c", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": call, "function": map[string]any{"arguments": piece}}}}}}})
			chunks = append(chunks, "data: "+string(b)+"\n\n")
		}
	}
	chunks = append(chunks, `data: {"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n", "data: [DONE]\n\n")
	s := r.NewStream("", true)
	var out strings.Builder
	done := false
	for _, c := range chunks {
		got, end := s.Chunk([]byte(c))
		out.Write(got)
		done = done || end
	}
	if !done {
		t.Fatal("[DONE] did not end the stream")
	}
	var content strings.Builder
	args := map[float64]*strings.Builder{}
	for _, ev := range events(t, out.String()) {
		if s, ok := dig(ev, "choices", 0, "delta", "content").(string); ok {
			content.WriteString(s)
		}
		if call, ok := dig(ev, "choices", 0, "delta", "tool_calls", 0).(map[string]any); ok {
			i := call["index"].(float64)
			if args[i] == nil {
				args[i] = &strings.Builder{}
			}
			args[i].WriteString(dig(call, "function", "arguments").(string))
		}
	}
	if content.String() != "mail a@b.com" {
		t.Fatalf("content = %q", content.String())
	}
	var first, second map[string]string
	if err := json.Unmarshal([]byte(args[0].String()), &first); err != nil || first["to"] != "a@b.com" {
		t.Fatalf("first call = %q", args[0].String())
	}
	if err := json.Unmarshal([]byte(args[1].String()), &second); err != nil || second["key"] != `back\slash` {
		t.Fatalf("second call = %q", args[1].String())
	}
}

// Where the stream is cut must not matter: a Placeholder with a word on
// either side restores whether it comes in one delta or in two.
func TestStreamRestoresPlaceholdersAgainstWordsAtEveryCut(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	text := "x" + p + "next"
	args := `{"to":"x` + p + `next"}`
	for _, tc := range []struct {
		name string
		full string
		wrap func(string) map[string]any
		read func(map[string]any) (string, bool)
	}{
		{"content", text,
			func(s string) map[string]any { return map[string]any{"content": s} },
			func(ev map[string]any) (string, bool) {
				s, ok := dig(ev, "choices", 0, "delta", "content").(string)
				return s, ok
			}},
		{"tool arguments", args,
			func(s string) map[string]any {
				return map[string]any{"tool_calls": []any{map[string]any{"index": 0, "function": map[string]any{"arguments": s}}}}
			},
			func(ev map[string]any) (string, bool) {
				s, ok := dig(ev, "choices", 0, "delta", "tool_calls", 0, "function", "arguments").(string)
				return s, ok
			}},
	} {
		for cut := 0; cut <= len(tc.full); cut++ {
			var chunks []string
			for _, piece := range []string{tc.full[:cut], tc.full[cut:]} {
				if piece == "" {
					continue
				}
				b, _ := json.Marshal(map[string]any{"id": "c", "choices": []any{map[string]any{"index": 0, "delta": tc.wrap(piece)}}})
				chunks = append(chunks, "data: "+string(b)+"\n\n")
			}
			chunks = append(chunks, `data: {"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\n", "data: [DONE]\n\n")
			var got strings.Builder
			for _, ev := range events(t, feed(t, r.NewStream("", true), chunks)) {
				if s, ok := tc.read(ev); ok {
					got.WriteString(s)
				}
			}
			if want := strings.ReplaceAll(tc.full, p, "a@b.com"); got.String() != want {
				t.Errorf("%s cut at %d: %q, want %q", tc.name, cut, got.String(), want)
			}
		}
	}
}

func TestStreamResponses(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	var chunks []string
	for i, piece := range split("mail "+p, 5) {
		b, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "item_id": "m1", "output_index": 0, "content_index": 0, "delta": piece, "sequence_number": i})
		chunks = append(chunks, "event: response.output_text.delta\ndata: "+string(b)+"\n\n")
	}
	for i, piece := range split(`{"to":"`+p+`"}`, 6) {
		b, _ := json.Marshal(map[string]any{"type": "response.function_call_arguments.delta", "item_id": "f1", "output_index": 1, "delta": piece, "sequence_number": 100 + i})
		chunks = append(chunks, "event: response.function_call_arguments.delta\ndata: "+string(b)+"\n\n")
	}
	chunks = append(chunks, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"mail "+p+"\"}]}]}}\n\n")
	out := feed(t, r.NewStream("", true), chunks)
	var text, args strings.Builder
	var seqs []float64
	for _, ev := range events(t, out) {
		switch ev["type"] {
		case "response.output_text.delta":
			text.WriteString(ev["delta"].(string))
			seqs = append(seqs, ev["sequence_number"].(float64))
		case "response.function_call_arguments.delta":
			args.WriteString(ev["delta"].(string))
		case "response.completed":
			if got := dig(ev, "response", "output", 0, "content", 0, "text"); got != "mail a@b.com" {
				t.Fatalf("completed text = %v", got)
			}
		}
	}
	if text.String() != "mail a@b.com" || args.String() != `{"to":"a@b.com"}` {
		t.Fatalf("text = %q args = %q", text.String(), args.String())
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("sequence numbers out of order: %v", seqs)
		}
	}
}

// However a stream ends, nothing comes after its last event to release it, so
// the event goes out even when its text ends like the start of a Placeholder,
// as code cut short by a token limit can.
func TestStreamEndingEventsAreNeverHeld(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	for _, typ := range []string{"response.completed", "response.incomplete", "response.failed"} {
		for _, tail := range []string{"", "{", "{{", "{{EMA"} {
			text := "to " + p + " func main() " + tail
			b, _ := json.Marshal(map[string]any{"type": typ, "response": map[string]any{"output": []any{
				map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": text}}},
			}}})
			name := typ + " ending in " + tail
			for how, chunks := range map[string][]string{
				"whole":    {"event: " + typ + "\ndata: " + string(b) + "\n\n"},
				"by lines": {"event: " + typ, "data: " + string(b)},
			} {
				s := r.NewStream("", true)
				var out strings.Builder
				done := false
				for _, c := range chunks {
					got, end := s.Chunk([]byte(c))
					out.Write(got)
					done = done || end
				}
				if !done {
					t.Errorf("%s, %s: the stream did not end", name, how)
				}
				evs := events(t, out.String())
				if len(evs) != 1 || evs[0]["type"] != typ {
					t.Fatalf("%s, %s: delivered %q", name, how, out.String())
				}
				want := "to a@b.com func main() " + tail
				if got := dig(evs[0], "response", "output", 0, "content", 0, "text"); got != want {
					t.Errorf("%s, %s: text = %v", name, how, got)
				}
				if n := s.Tally().Back[p]; n != 1 {
					t.Errorf("%s, %s: tally = %d", name, how, n)
				}
			}
		}
	}
}

// A delta held when the stream ends goes out with the event that ends it.
func TestStreamEndingEventReleasesAHeldDelta(t *testing.T) {
	r, _ := newRestorer(t)
	s := r.NewStream("", true)
	delta := `{"type":"response.output_text.delta","item_id":"m1","output_index":0,"content_index":0,"delta":"code {"}`
	if out, done := s.Chunk([]byte("event: response.output_text.delta\ndata: " + delta + "\n\n")); len(out) != 0 || done {
		t.Fatalf("the delta was not held: %q, done %v", out, done)
	}
	out, done := s.Chunk([]byte("event: response.incomplete\ndata: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"r1\"}}\n\n"))
	evs := events(t, string(out))
	if !done || len(evs) != 2 || evs[0]["delta"] != "code {" || evs[1]["type"] != "response.incomplete" {
		t.Fatalf("delivered %q, done %v", out, done)
	}
}

func TestStreamGemini(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	pieces := split("mail "+p+" done", 6)
	var chunks []string
	for i, piece := range pieces {
		cand := map[string]any{"index": 0, "content": map[string]any{"role": "model", "parts": []any{map[string]any{"text": piece}}}}
		if i == len(pieces)-1 {
			cand["finishReason"] = "STOP"
		}
		b, _ := json.Marshal(map[string]any{"candidates": []any{cand}})
		chunks = append(chunks, "data: "+string(b)+"\r\n\r\n")
	}
	out := feed(t, r.NewStream("", true), chunks)
	var text strings.Builder
	for _, ev := range events(t, out) {
		text.WriteString(dig(ev, "candidates", 0, "content", "parts", 0, "text").(string))
	}
	if text.String() != "mail a@b.com done" {
		t.Fatalf("text = %q\n%q", text.String(), out)
	}
}

func TestStreamWithoutHoldingRestoresWholePlaceholders(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	s := r.NewStream("", false)
	got, _ := s.Chunk([]byte("event: content_block_delta\n"))
	if string(got) != "event: content_block_delta\n" {
		t.Fatalf("stateless stream held an event line: %q", got)
	}
	got, _ = s.Chunk([]byte("data: " + textDelta("mail "+p) + "\n"))
	if !strings.Contains(string(got), "mail a@b.com") {
		t.Fatalf("got %q", got)
	}
	got, _ = s.Chunk([]byte(`[{"candidates":[{"content":{"parts":[{"text":"` + p + `"}]}}]}` + "\n"))
	if !strings.Contains(string(got), `"text":"a@b.com"`) {
		t.Fatalf("raw JSON line not restored: %q", got)
	}
}

// feedBare runs bare JSON chunks through a Stream and frames what comes out
// as the OpenAI chat and Gemini handlers do: "data: <chunk>\n\n", nothing
// for a dropped chunk.
func feedBare(t *testing.T, s *Stream, chunks []string) string {
	t.Helper()
	var out strings.Builder
	for _, c := range chunks {
		got, _ := s.Chunk([]byte(c))
		if len(got) == 0 {
			continue
		}
		out.WriteString("data: " + string(got) + "\n\n")
	}
	return out.String()
}

func TestStreamBareOpenAIChunks(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	q := v.Placeholder("", "SECRET", `qu"ote`)
	var chunks []string
	for _, piece := range split("mail "+p+" then "+p, 3) {
		b, _ := json.Marshal(map[string]any{"id": "c", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": piece}}}})
		chunks = append(chunks, string(b))
	}
	for _, piece := range split(`{"key":"`+q+`"}`, 4) {
		b, _ := json.Marshal(map[string]any{"id": "c", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": 0, "function": map[string]any{"arguments": piece}}}}}}})
		chunks = append(chunks, string(b))
	}
	chunks = append(chunks, `{"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`)
	out := feedBare(t, r.NewStream("", true), chunks)
	var content, args strings.Builder
	for _, ev := range events(t, out) {
		if s, ok := dig(ev, "choices", 0, "delta", "content").(string); ok {
			content.WriteString(s)
		}
		if s, ok := dig(ev, "choices", 0, "delta", "tool_calls", 0, "function", "arguments").(string); ok {
			args.WriteString(s)
		}
	}
	if content.String() != "mail a@b.com then a@b.com" {
		t.Fatalf("content = %q\n%s", content.String(), out)
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(args.String()), &parsed); err != nil || parsed["key"] != `qu"ote` {
		t.Fatalf("arguments = %q", args.String())
	}
	if !strings.Contains(out, `"finish_reason":"tool_calls"`) {
		t.Fatalf("the final chunk went missing:\n%s", out)
	}
}

func TestStreamBareGeminiChunks(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "PHONE", "13800138000")
	pieces := split("call "+p, 4)
	var chunks []string
	for i, piece := range pieces {
		cand := map[string]any{"index": 0, "content": map[string]any{"parts": []any{map[string]any{"text": piece}}}}
		if i == len(pieces)-1 {
			cand["finishReason"] = "STOP"
		}
		b, _ := json.Marshal(map[string]any{"candidates": []any{cand}})
		chunks = append(chunks, string(b))
	}
	out := feedBare(t, r.NewStream("", true), chunks)
	var text strings.Builder
	for _, ev := range events(t, out) {
		text.WriteString(dig(ev, "candidates", 0, "content", "parts", 0, "text").(string))
	}
	if text.String() != "call 13800138000" {
		t.Fatalf("text = %q\n%s", text.String(), out)
	}
}
