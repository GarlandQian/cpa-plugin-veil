package restore

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBodyTallyCountsWhatItRestoresAndMisses(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	gone := "{{EMAIL_aaaaaaaa}}" // of a Kind Veil masks, but not in the Vault
	body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]any{
		"content": "to " + p + " and " + strings.ToLower(p) + ", not " + gone + " nor EMAIL_bbbbbbbb nor {{NOTAKIND_cccccccc}}",
	}}}})
	var tally Tally
	out := r.BodyTally("", body, &tally)
	if !strings.Contains(string(out), "a@b.com") {
		t.Fatalf("nothing restored: %s", out)
	}
	if tally.Back[p] != 2 || len(tally.Back) != 1 {
		t.Errorf("back = %v", tally.Back)
	}
	if tally.Unrestored[gone] != 1 || len(tally.Unrestored) != 1 {
		t.Errorf("unrestored = %v", tally.Unrestored)
	}
	if r.Body("", body) == nil {
		t.Error("Body without a tally restored nothing")
	}
}

func TestStandInsAreCounted(t *testing.T) {
	r, v := newRestorer(t)
	s := v.Placeholder("", "USERNAME", "garland")
	var tally Tally
	if out, ok := r.replace("", "/Users/"+s+"/work and /home/"+s, false, &tally); !ok || strings.Contains(out, s) {
		t.Fatalf("stand-in not restored: %q", out)
	}
	if tally.Back[s] != 2 {
		t.Fatalf("back = %v", tally.Back)
	}
}

// Wherever a stream is cut, each place counts once, held or not.
func TestStreamTallyCountsEachPlaceOnce(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	text := "x" + p + " and " + p + "next"
	sse := func(piece string) string {
		b, _ := json.Marshal(map[string]any{"id": "c", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": piece}}}})
		return "data: " + string(b) + "\n\n"
	}
	bare := func(piece string) string {
		b, _ := json.Marshal(map[string]any{"id": "c", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": piece}}}})
		return string(b)
	}
	for name, frame := range map[string]func(string) string{"sse": sse, "bare": bare} {
		for cut := 0; cut <= len(text); cut++ {
			var chunks []string
			for _, piece := range []string{text[:cut], text[cut:]} {
				if piece != "" {
					chunks = append(chunks, frame(piece))
				}
			}
			s := r.NewStream("", true)
			feed(t, s, chunks)
			if n := s.Tally().Back[p]; n != 2 {
				t.Errorf("%s cut at %d: counted %d", name, cut, n)
			}
		}
	}

	// A Claude stream a line at a time, the placeholder in three-byte pieces.
	var chunks []string
	for _, piece := range split("mail "+p+" now", 3) {
		chunks = append(chunks, claudeEvent("content_block_delta", textDelta(piece))...)
	}
	s := r.NewStream("", true)
	feed(t, s, chunks)
	if n := s.Tally().Back[p]; n != 1 {
		t.Fatalf("claude stream counted %d", n)
	}
}
