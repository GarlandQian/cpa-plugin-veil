package mask

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

const email = "test@acme-corp.cn"

var placeholderRe = regexp.MustCompile(`\{\{[A-Z_]+_[a-z2-7]{8,}\}\}`)

func newMasker(t *testing.T) (*Masker, *vault.Vault) {
	t.Helper()
	d, err := detect.New(nil, detect.Options{})
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
		{"claude system string", `{"system":"contact test@acme-corp.cn"}`},
		{"claude system blocks", `{"system":[{"type":"text","text":"test@acme-corp.cn","cache_control":{"type":"ephemeral"}}]}`},
		{"claude tool_result", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"test@acme-corp.cn"}]}]}]}`},
		{"claude tool_use input", `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"send","input":{"to":"test@acme-corp.cn","name":"test@acme-corp.cn"}}]}]}`},
		{"claude document text source", `{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"text","media_type":"text/plain","data":"test@acme-corp.cn"}}]}]}`},
		{"openai chat", `{"messages":[{"role":"user","content":"test@acme-corp.cn"},{"role":"user","content":[{"type":"text","text":"test@acme-corp.cn"}]}]}`},
		{"openai tool call arguments", `{"messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"send","arguments":"{\"to\":\"test@acme-corp.cn\"}"}}]}]}`},
		{"openai tool message", `{"messages":[{"role":"tool","tool_call_id":"c1","content":"sent to test@acme-corp.cn"}]}`},
		{"responses", `{"instructions":"test@acme-corp.cn","input":[{"role":"user","content":[{"type":"input_text","text":"test@acme-corp.cn"}]},{"type":"function_call","call_id":"c1","name":"send","arguments":"{\"to\":\"test@acme-corp.cn\"}"},{"type":"function_call_output","call_id":"c1","output":"test@acme-corp.cn"}]}`},
		{"responses string input", `{"input":"test@acme-corp.cn"}`},
		{"gemini", `{"systemInstruction":{"parts":[{"text":"test@acme-corp.cn"}]},"contents":[{"role":"user","parts":[{"text":"test@acme-corp.cn"}]},{"role":"model","parts":[{"functionCall":{"name":"send","args":{"to":"test@acme-corp.cn"}},"thoughtSignature":"sig"}]},{"role":"user","parts":[{"functionResponse":{"name":"send","response":{"result":"test@acme-corp.cn"}}}]}]}`},
		{"gemini cli", `{"model":"gemini-2.5-pro","project":"p","request":{"contents":[{"role":"user","parts":[{"text":"test@acme-corp.cn"}]}]}}`},
		{"image prompt", `{"prompt":["test@acme-corp.cn","hello"]}`},
		{"embeddings", `{"input":["test@acme-corp.cn"]}`},
		{"metadata", `{"metadata":{"note":"test@acme-corp.cn","user_id":"test@acme-corp.cn"}}`},
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
			want := strings.Count(tc.body, `"user_id":"test@acme-corp.cn"`)
			if rest != want {
				t.Fatalf("%d copies of the email left, want %d: %s", rest, want, got)
			}
		})
	}
}

func TestLeavesSealedBlocksAndIdentifiersAlone(t *testing.T) {
	m, _ := newMasker(t)
	for _, body := range []string{
		`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"test@acme-corp.cn","signature":"sig"},{"type":"redacted_thinking","data":"test@acme-corp.cn"}]}]}`,
		`{"input":[{"type":"reasoning","id":"r1","summary":[{"type":"summary_text","text":"test@acme-corp.cn"}],"encrypted_content":"x"}]}`,
		`{"contents":[{"role":"model","parts":[{"text":"test@acme-corp.cn","thought":true,"thoughtSignature":"sig"}]}]}`,
		`{"model":"test@acme-corp.cn","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"test@acme-corp.cn"}},{"type":"image_url","image_url":{"url":"https://x/test@acme-corp.cn"}}]}]}`,
		`{"tools":[{"name":"test@acme-corp.cn","input_schema":{"type":"object","properties":{"to":{"type":"string","enum":["test@acme-corp.cn"]}}}}]}`,
		`{"previous_response_id":"test@acme-corp.cn","prompt_cache_key":"test@acme-corp.cn"}`,
		`{"messages":[{"role":"user","content":"data:text/plain;base64,test@acme-corp.cn"}]}`,
	} {
		if got := mask(t, m, "", body); got != body {
			t.Fatalf("changed %s\n     to %s", body, got)
		}
	}
}

func TestToolDescriptionsAreMasked(t *testing.T) {
	m, _ := newMasker(t)
	got := mask(t, m, "", `{"tools":[{"name":"send","description":"mail test@acme-corp.cn","input_schema":{"properties":{"to":{"description":"defaults to test@acme-corp.cn"}}}}]}`)
	if strings.Contains(got, email) {
		t.Fatalf("description kept the email: %s", got)
	}
	if !strings.Contains(got, `"name":"send"`) {
		t.Fatalf("tool name changed: %s", got)
	}
}

func TestArgumentsStayValidJSON(t *testing.T) {
	m, v := newMasker(t)
	body := `{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"run","arguments":"{\"cmd\":\"mail \\\"test@acme-corp.cn\\\"\",\"n\":12345678901234567890}"}}]}]}`
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
	body := `{"messages":[{"role":"user","content":"mail test@acme-corp.cn, call 13800138000"}]}`
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
	body := `{"input":"test@acme-corp.cn"}`
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
	_, report, err := m.Mask("", []byte(`{"system":"test@acme-corp.cn","messages":[{"role":"user","content":"test@acme-corp.cn and 13800138000"}]}`))
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
	if got := mask(t, m, "", `{"input":"a test@acme-corp.cn","input":"b test@acme-corp.cn"}`); strings.Contains(got, email) {
		t.Fatalf("duplicate key leaked: %s", got)
	}
	for _, body := range []string{`["test@acme-corp.cn"]`, `"test@acme-corp.cn"`, `not json test@acme-corp.cn`} {
		if out, _, _ := m.Mask("", []byte(body)); out != nil {
			t.Fatalf("non-object body changed: %s", out)
		}
	}
}

func TestActions(t *testing.T) {
	m, _ := newMasker(t)
	m = m.WithPolicy(m.detector, map[string]Action{"EMAIL": Warn, "PHONE": Block})
	out, report, err := m.Mask("", []byte(`{"input":"mail test@acme-corp.cn"}`))
	if err != nil || out != nil {
		t.Fatalf("warned value changed the body: %s %v", out, err)
	}
	if report.Warned["EMAIL"] != 1 || len(report.WarnedPaths) != 1 {
		t.Fatalf("report = %+v", report)
	}
	_, report, err = m.Mask("", []byte(`{"messages":[{"role":"user","content":"call 13800138000"}]}`))
	if err != nil || report.Blocked["PHONE"] != 1 || report.BlockedPaths[0] != "messages[0].content" {
		t.Fatalf("report = %+v, %v", report, err)
	}
	// A blocked request was never sent, so its text has no Sent form: once
	// PHONE is masked again, the same text masks.
	unblocked := m.WithPolicy(m.detector, nil)
	if got := mask(t, unblocked, "", `{"messages":[{"role":"user","content":"call 13800138000"}]}`); strings.Contains(got, "13800138000") {
		t.Fatalf("text of a blocked request kept a Sent form: %s", got)
	}
}

func TestMalformedJSONIsAnError(t *testing.T) {
	m, _ := newMasker(t)
	for _, body := range []string{`{"input":"test@acme-corp.cn"`, ` [1,`} {
		if _, _, err := m.Mask("", []byte(body)); err != ErrMalformed {
			t.Fatalf("%q: err = %v", body, err)
		}
	}
}

func TestSecretNamedFieldsAreMaskedWhole(t *testing.T) {
	m, _ := newMasker(t)
	got := mask(t, m, "", `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"deploy","input":{"api_key":"plainwordsonly","db_pass":"another-plain-one","max_tokens":"1234567890","note":"plainwordsonly"}}]}]}`)
	if strings.Contains(got, `"api_key":"plainwordsonly"`) || strings.Contains(got, "another-plain-one") {
		t.Fatalf("secret-named fields kept their values: %s", got)
	}
	if !strings.Contains(got, `"max_tokens":"1234567890"`) || !strings.Contains(got, `"note":"{{SECRET_`) {
		t.Fatalf("a count of tokens was masked, or a known value was missed: %s", got)
	}
}
