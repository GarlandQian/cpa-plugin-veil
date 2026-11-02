package mask

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

const email = "test@example.com"

var placeholderRe = regexp.MustCompile(`\{\{[A-Z_]+_[a-z2-7]{8,}\}\}`)

func newMasker(t *testing.T) (*Masker, *vault.Vault) {
	t.Helper()
	d, err := detect.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New([]byte("0123456789abcdef0123456789abcdef"), 0)
	return New(d, v), v
}

func mask(t *testing.T, m *Masker, scope, body string) string {
	t.Helper()
	out, _, err := m.Mask(scope, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		return body
	}
	if !json.Valid(out) {
		t.Fatalf("masked body is not JSON: %s", out)
	}
	return string(out)
}

func TestMasksEveryClientFormat(t *testing.T) {
	m, v := newMasker(t)
	p := v.Placeholder("", "EMAIL", email)
	cases := []struct{ name, body string }{
		{"claude system string", `{"system":"contact test@example.com"}`},
		{"claude system blocks", `{"system":[{"type":"text","text":"test@example.com","cache_control":{"type":"ephemeral"}}]}`},
		{"claude tool_result", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"test@example.com"}]}]}]}`},
		{"claude tool_use input", `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"send","input":{"to":"test@example.com","name":"test@example.com"}}]}]}`},
		{"claude document text source", `{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"test@example.com"}}]}]}`},
		{"openai chat", `{"messages":[{"role":"user","content":"test@example.com"},{"role":"user","content":[{"type":"text","text":"test@example.com"}]}]}`},
		{"openai tool call arguments", `{"messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"send","arguments":"{\"to\":\"test@example.com\"}"}}]}]}`},
		{"openai tool message", `{"messages":[{"role":"tool","tool_call_id":"c1","content":"sent to test@example.com"}]}`},
		{"responses", `{"instructions":"test@example.com","input":[{"role":"user","content":[{"type":"input_text","text":"test@example.com"}]},{"type":"function_call","call_id":"c1","name":"send","arguments":"{\"to\":\"test@example.com\"}"},{"type":"function_call_output","call_id":"c1","output":"test@example.com"}]}`},
		{"responses string input", `{"input":"test@example.com"}`},
		{"gemini", `{"systemInstruction":{"parts":[{"text":"test@example.com"}]},"contents":[{"role":"user","parts":[{"text":"test@example.com"}]},{"role":"model","parts":[{"functionCall":{"name":"send","args":{"to":"test@example.com"}},"thoughtSignature":"sig"}]},{"role":"user","parts":[{"functionResponse":{"name":"send","response":{"result":"test@example.com"}}}]}]}`},
		{"gemini cli", `{"model":"gemini-2.5-pro","project":"p","request":{"contents":[{"role":"user","parts":[{"text":"test@example.com"}]}]}}`},
		{"image prompt", `{"prompt":["test@example.com","hello"]}`},
		{"embeddings", `{"input":["test@example.com"]}`},
		{"metadata", `{"metadata":{"note":"test@example.com","user_id":"test@example.com"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mask(t, m, "", tc.body)
			if !strings.Contains(got, p) {
				t.Fatalf("no placeholder in %s", got)
			}
			rest := strings.Count(got, email)
			// Identifiers stay as sent; a tool's own argument named "name"
			// does not.
			want := strings.Count(tc.body, `"user_id":"test@example.com"`)
			if rest != want {
				t.Fatalf("%d copies of the email left, want %d: %s", rest, want, got)
			}
		})
	}
}

func TestLeavesSealedBlocksAndIdentifiersAlone(t *testing.T) {
	m, _ := newMasker(t)
	for _, body := range []string{
		`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"test@example.com","signature":"sig"},{"type":"redacted_thinking","data":"test@example.com"}]}]}`,
		`{"input":[{"type":"reasoning","id":"r1","summary":[{"type":"summary_text","text":"test@example.com"}],"encrypted_content":"x"}]}`,
		`{"contents":[{"role":"model","parts":[{"text":"test@example.com","thought":true,"thoughtSignature":"sig"}]}]}`,
		`{"model":"test@example.com","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"test@example.com"}},{"type":"image_url","image_url":{"url":"https://x/test@example.com"}}]}]}`,
		`{"tools":[{"name":"test@example.com","input_schema":{"type":"object","properties":{"to":{"type":"string","enum":["test@example.com"]}}}}]}`,
		`{"previous_response_id":"test@example.com","prompt_cache_key":"test@example.com"}`,
		`{"messages":[{"role":"user","content":"data:text/plain;base64,test@example.com"}]}`,
	} {
		if got := mask(t, m, "", body); got != body {
			t.Fatalf("changed %s\n     to %s", body, got)
		}
	}
}

func TestToolDescriptionsAreMasked(t *testing.T) {
	m, _ := newMasker(t)
	got := mask(t, m, "", `{"tools":[{"name":"send","description":"mail test@example.com","input_schema":{"properties":{"to":{"description":"defaults to test@example.com"}}}}]}`)
	if strings.Contains(got, email) {
		t.Fatalf("description kept the email: %s", got)
	}
	if !strings.Contains(got, `"name":"send"`) {
		t.Fatalf("tool name changed: %s", got)
	}
}

func TestArgumentsStayValidJSON(t *testing.T) {
	m, v := newMasker(t)
	body := `{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"run","arguments":"{\"cmd\":\"mail \\\"test@example.com\\\"\",\"n\":12345678901234567890}"}}]}]}`
	got := mask(t, m, "", body)
	var parsed struct {
		Messages []struct {
			ToolCalls []struct {
				Function struct{ Arguments string } `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatal(err)
	}
	args := parsed.Messages[0].ToolCalls[0].Function.Arguments
	want := `{"cmd":"mail \"` + v.Placeholder("", "EMAIL", email) + `\"","n":12345678901234567890}`
	if args != want {
		t.Fatalf("arguments = %s\n     want %s", args, want)
	}
}

func TestMaskingIsStableAndIdempotent(t *testing.T) {
	m, _ := newMasker(t)
	body := `{"messages":[{"role":"user","content":"mail test@example.com, call 13800138000"}]}`
	first := mask(t, m, "", body)
	if second := mask(t, m, "", body); second != first {
		t.Fatalf("the same body masked twice differently:\n%s\n%s", first, second)
	}
	if again, _, _ := m.Mask("", []byte(first)); again != nil {
		t.Fatalf("masking a masked body changed it: %s", again)
	}
	if len(placeholderRe.FindAllString(first, -1)) != 2 {
		t.Fatalf("expected two placeholders: %s", first)
	}
}

func TestScopesGetDifferentPlaceholders(t *testing.T) {
	m, _ := newMasker(t)
	body := `{"input":"test@example.com"}`
	if mask(t, m, "a", body) == mask(t, m, "b", body) {
		t.Fatal("two Caller scopes got the same placeholder")
	}
}

// A secret found by its context in one field is masked where it appears
// without context in another field of the same request.
func TestValueFoundOnceIsMaskedAcrossTheRequest(t *testing.T) {
	m, _ := newMasker(t)
	body := `{"messages":[{"role":"user","content":"the value Xk9-hunter2-Qz7 again"},{"role":"user","content":"password: Xk9-hunter2-Qz7"}]}`
	got := mask(t, m, "", body)
	if strings.Contains(got, "Xk9-hunter2-Qz7") {
		t.Fatalf("value leaked where it had no context: %s", got)
	}
}

func TestKnownValueIsMaskedInLaterRequests(t *testing.T) {
	m, _ := newMasker(t)
	mask(t, m, "", `{"input":"password: Xk9-hunter2-Qz7"}`)
	got := mask(t, m, "", `{"input":"run it with Xk9-hunter2-Qz7 now"}`)
	if strings.Contains(got, "Xk9-hunter2-Qz7") {
		t.Fatalf("known value leaked: %s", got)
	}
	if other := mask(t, m, "other", `{"input":"run it with Xk9-hunter2-Qz7 now"}`); !strings.Contains(other, "Xk9-hunter2-Qz7") {
		t.Fatalf("a known value crossed into another Caller scope: %s", other)
	}
}

// Text already sent keeps its Sent form when a value in it is learned later,
// so the prompt prefix the provider cached still matches.
func TestSentTextKeepsItsForm(t *testing.T) {
	m, _ := newMasker(t)
	early := `{"role":"user","content":"keep Xk9-hunter2-Qz7 in mind"}`
	first := mask(t, m, "", `{"messages":[`+early+`]}`)
	if !strings.Contains(first, "Xk9-hunter2-Qz7") {
		t.Fatalf("a value without context was masked: %s", first)
	}
	later := mask(t, m, "", `{"messages":[`+early+`,{"role":"user","content":"password: Xk9-hunter2-Qz7"}]}`)
	if !strings.Contains(later, `"keep Xk9-hunter2-Qz7 in mind"`) {
		t.Fatalf("sent text changed form: %s", later)
	}
	if strings.Count(later, "Xk9-hunter2-Qz7") != 1 {
		t.Fatalf("the new text was not masked: %s", later)
	}
}

func TestReportHasPathsAndCountsOnly(t *testing.T) {
	m, _ := newMasker(t)
	_, report, err := m.Mask("", []byte(`{"system":"test@example.com","messages":[{"role":"user","content":"test@example.com and 13800138000"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(report.Paths, ",") != "system,messages[0].content" {
		t.Fatalf("paths = %v", report.Paths)
	}
	if report.Counts["EMAIL"] != 2 || report.Counts["PHONE"] != 1 || report.Total() != 3 {
		t.Fatalf("counts = %v", report.Counts)
	}
}

func TestDuplicateKeysAndNonObjects(t *testing.T) {
	m, _ := newMasker(t)
	if got := mask(t, m, "", `{"input":"a test@example.com","input":"b test@example.com"}`); strings.Contains(got, email) {
		t.Fatalf("duplicate key leaked: %s", got)
	}
	for _, body := range []string{`["test@example.com"]`, `"test@example.com"`, `not json test@example.com`} {
		if out, _, _ := m.Mask("", []byte(body)); out != nil {
			t.Fatalf("non-object body changed: %s", out)
		}
	}
}
