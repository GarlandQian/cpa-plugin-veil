package restore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

func newRestorer(t *testing.T) (*Restorer, *vault.Vault) {
	t.Helper()
	v := vault.New([]byte("0123456789abcdef0123456789abcdef"), 0)
	return New(v), v
}

func TestTextAcceptsLooseSpellings(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("s", "ID_CARD", "11010519900307743X")
	core := strings.Trim(p, "{}") // ID_CARD_xxxxxxxx
	kind, hash := core[:len("ID_CARD")], core[len("ID_CARD_"):]
	for _, written := range []string{
		p,
		"{{ " + core + " }}",
		"{" + core + "}",
		"{{" + core + "}",
		core,
		"{{" + strings.ToLower(kind) + "_" + strings.ToUpper(hash) + "}}",
	} {
		got, ok := r.Text("s", "id is "+written+".")
		if !ok || got != "id is 11010519900307743X." {
			t.Errorf("%q restored to %q", written, got)
		}
	}
}

func TestTextLeavesOtherTokensAlone(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("s", "EMAIL", "a@b.com")
	for _, text := range []string{
		"ACCOUNT_abcdefgh is not ours",
		"x" + strings.Trim(p, "{}"),     // glued to a word
		strings.Trim(p, "{}") + "_more", // continues as a word
		"{{EMAIL_aaaaaaaa}}",
	} {
		if got, ok := r.Text("s", text); ok {
			t.Errorf("%q restored to %q", text, got)
		}
	}
	if got, ok := r.Text("other", p); ok {
		t.Fatalf("a placeholder restored in another scope: %q", got)
	}
}

func TestBodyRestoresEveryFormat(t *testing.T) {
	r, v := newRestorer(t)
	email := v.Placeholder("", "EMAIL", "a@b.com")
	quoted := v.Placeholder("", "SECRET", `pa"ss\word`)
	cases := []struct{ name, body, want string }{
		{"claude text and tool_use",
			`{"content":[{"type":"text","text":"mail ` + email + `"},{"type":"tool_use","id":"t1","name":"send","input":{"to":"` + email + `","name":"` + email + `"}}]}`,
			`{"content":[{"type":"text","text":"mail a@b.com"},{"type":"tool_use","id":"t1","name":"send","input":{"to":"a@b.com","name":"a@b.com"}}]}`},
		{"openai chat tool call",
			`{"choices":[{"message":{"role":"assistant","content":"ok","tool_calls":[{"id":"c1","type":"function","function":{"name":"login","arguments":"{\"password\":\"` + quoted + `\"}"}}]}}]}`,
			`{"choices":[{"message":{"role":"assistant","content":"ok","tool_calls":[{"id":"c1","type":"function","function":{"name":"login","arguments":"{\"password\":\"pa\\\"ss\\\\word\"}"}}]}}]}`},
		{"responses output",
			`{"output":[{"type":"message","content":[{"type":"output_text","text":"` + email + `"}]},{"type":"function_call","call_id":"c1","name":"send","arguments":"{\"to\":\"` + email + `\"}"}]}`,
			`{"output":[{"type":"message","content":[{"type":"output_text","text":"a@b.com"}]},{"type":"function_call","call_id":"c1","name":"send","arguments":"{\"to\":\"a@b.com\"}"}]}`},
		{"gemini",
			`{"candidates":[{"content":{"parts":[{"text":"` + email + `"},{"functionCall":{"name":"send","args":{"to":"` + email + `"}}}]}}]}`,
			`{"candidates":[{"content":{"parts":[{"text":"a@b.com"},{"functionCall":{"name":"send","args":{"to":"a@b.com"}}}]}}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := r.Body("", []byte(tc.body))
			if string(got) != tc.want {
				t.Fatalf("got  %s\nwant %s", got, tc.want)
			}
			if !json.Valid(got) {
				t.Fatal("restored body is not JSON")
			}
		})
	}
}

func TestBodyLeavesSealedBlocksAndIdentifiers(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	for _, body := range []string{
		`{"content":[{"type":"thinking","thinking":"` + p + `","signature":"sig"}]}`,
		`{"output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"` + p + `"}]}]}`,
		`{"candidates":[{"content":{"parts":[{"text":"` + p + `","thought":true}]}}]}`,
		`{"id":"` + p + `","model":"` + p + `"}`,
	} {
		if got := r.Body("", []byte(body)); got != nil {
			t.Fatalf("changed %s\n     to %s", body, got)
		}
	}
}

func TestBodyRestoresPlainText(t *testing.T) {
	r, v := newRestorer(t)
	p := v.Placeholder("", "EMAIL", "a@b.com")
	if got := r.Body("", []byte("mail "+p)); string(got) != "mail a@b.com" {
		t.Fatalf("got %q", got)
	}
	if got := r.Body("", []byte("\xff"+p)); got != nil {
		t.Fatalf("binary body changed: %q", got)
	}
	if got := r.Body("empty-scope", []byte("mail "+p)); got != nil {
		t.Fatalf("a scope without placeholders changed the body: %q", got)
	}
}
