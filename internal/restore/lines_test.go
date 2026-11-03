package restore

import (
	"encoding/json"
	"strings"
	"testing"
)

// viaLines delivers a stream as CPA v8's Codex path does: one SSE line per
// chunk, its line ending as given (none, as v8 sends it, or \n or \r\n), and
// the blank separator as an empty chunk the host passes by without a plugin.
// With no endings, the host's framer joins the chunks it gets with line
// breaks, so the result does too.
func viaLines(t *testing.T, s *Stream, lines []string, ending string) string {
	t.Helper()
	var out []string
	for _, line := range lines {
		if line == "" {
			out = append(out, ending)
			continue
		}
		got, _ := s.Chunk([]byte(line + ending))
		if len(got) > 0 {
			out = append(out, string(got))
		}
	}
	if ending == "" {
		return strings.Join(out, "\n")
	}
	return strings.Join(out, "")
}

// sseFrames parses an SSE stream into its frames, each its fields by name.
func sseFrames(t *testing.T, stream string) []map[string]string {
	t.Helper()
	var frames []map[string]string
	cur := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(stream, "\r\n", "\n"), "\n") {
		if line == "" {
			if len(cur) > 0 {
				frames = append(frames, cur)
				cur = map[string]string{}
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("not an SSE field: %q in\n%s", line, stream)
		}
		if strings.Contains(value, "event:") || strings.Contains(value, "data:") && name != "data" {
			t.Fatalf("two fields on one line: %q in\n%s", line, stream)
		}
		cur[name] += strings.TrimPrefix(value, " ")
	}
	if len(cur) > 0 {
		frames = append(frames, cur)
	}
	return frames
}

func responsesLines(p string) []string {
	event := func(typ string, body map[string]any) []string {
		body["type"] = typ
		b, _ := json.Marshal(body)
		return []string{"event: " + typ, "data: " + string(b), ""}
	}
	var lines []string
	lines = append(lines, event("response.created", map[string]any{"response": map[string]any{"id": "r1"}})...)
	for _, piece := range []string{"mail " + p[:9], p[9:] + " ok"} {
		lines = append(lines, event("response.output_text.delta", map[string]any{"item_id": "m1", "output_index": 0, "content_index": 0, "delta": piece})...)
	}
	args := `{"to":"` + p + `"}`
	for _, piece := range []string{args[:12], args[12:]} {
		lines = append(lines, event("response.function_call_arguments.delta", map[string]any{"item_id": "f1", "output_index": 1, "delta": piece})...)
	}
	lines = append(lines, event("response.completed", map[string]any{"response": map[string]any{"id": "r1"}})...)
	return lines
}

// A Responses stream with event lines restores whatever line endings the
// host keeps, and every event still reaches the client as an event line and
// a data line of its own.
func TestStreamResponsesLinePerChunkWithAnyEnding(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	for name, ending := range map[string]string{"none": "", "lf": "\n", "crlf": "\r\n"} {
		out := viaLines(t, r.NewStream("", true), responsesLines(p), ending)
		frames := sseFrames(t, out)
		var text, args strings.Builder
		types := map[string]bool{}
		for _, f := range frames {
			var data map[string]any
			if err := json.Unmarshal([]byte(f["data"]), &data); err != nil {
				t.Fatalf("%s: frame without a JSON data line: %v in\n%s", name, f, out)
			}
			if f["event"] != data["type"] {
				t.Fatalf("%s: event %q carries data of %q in\n%s", name, f["event"], data["type"], out)
			}
			types[f["event"]] = true
			switch data["type"] {
			case "response.output_text.delta":
				text.WriteString(data["delta"].(string))
			case "response.function_call_arguments.delta":
				args.WriteString(data["delta"].(string))
			}
		}
		if !types["response.created"] || !types["response.completed"] || len(frames) != 6 {
			t.Fatalf("%s: frames %v in\n%s", name, frames, out)
		}
		if text.String() != "mail a@b.com ok" || args.String() != `{"to":"a@b.com"}` {
			t.Fatalf("%s: text %q, args %q", name, text.String(), args.String())
		}
	}
}

// A stream of data lines only, with no endings, goes through as it came,
// restored.
func TestStreamDataOnlyLinePerChunkWithoutEndings(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	var lines []string
	for _, piece := range []string{"to " + p[:6], p[6:] + "."} {
		b, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "item_id": "m1", "output_index": 0, "content_index": 0, "delta": piece})
		lines = append(lines, "data: "+string(b), "")
	}
	lines = append(lines, `data: {"type":"response.completed"}`, "")
	var text strings.Builder
	for _, f := range sseFrames(t, viaLines(t, r.NewStream("", true), lines, "")) {
		var data map[string]any
		if err := json.Unmarshal([]byte(f["data"]), &data); err != nil {
			t.Fatalf("frame %v", f)
		}
		if d, ok := data["delta"].(string); ok {
			text.WriteString(d)
		}
	}
	if text.String() != "to a@b.com." {
		t.Fatalf("text %q", text.String())
	}
}

// An event line held when holding stops, as a second stream of the same
// request starts, goes out on a line of its own.
func TestStreamHeldEventLineSurvivesStopHolding(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	b, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "item_id": "m1", "output_index": 0, "content_index": 0, "delta": "to " + p})
	s := r.NewStream("", true)
	var out []string
	if got, _ := s.Chunk([]byte("event: response.output_text.delta")); len(got) > 0 {
		out = append(out, string(got))
	}
	s.StopHolding()
	if got, _ := s.Chunk([]byte("data: " + string(b))); len(got) > 0 {
		out = append(out, string(got))
	}
	frames := sseFrames(t, strings.Join(out, "\n")+"\n\n")
	if len(frames) != 1 || frames[0]["event"] != "response.output_text.delta" || !strings.Contains(frames[0]["data"], "a@b.com") {
		t.Fatalf("frames %v from %q", frames, out)
	}
}
