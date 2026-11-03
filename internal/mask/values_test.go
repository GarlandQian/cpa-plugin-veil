package mask

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
)

// fakeToken is a GitHub token's shape, made at run time so no token is
// written in the source.
func fakeToken() string {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(7))
	b := make([]byte, 36)
	for i := range b {
		b[i] = alnum[r.Intn(len(alnum))]
	}
	return "ghp" + "_" + string(b)
}

func body(t *testing.T, texts ...string) []byte {
	t.Helper()
	var msgs []map[string]string
	for _, s := range texts {
		msgs = append(msgs, map[string]string{"role": "user", "content": s})
	}
	raw, err := json.Marshal(map[string]any{"messages": msgs})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestValuesTellEachValueWithoutIt(t *testing.T) {
	m, v := newMasker(t)
	m = m.WithPolicy(m.detector, map[string]Action{"PHONE": Warn}).WithValues(true)
	const phone = "13800138000"
	token := fakeToken()
	in := body(t, "mail "+email+" 我的手机号是 "+phone+" token "+token, "again "+email)
	out, report, err := m.Mask("s", in)
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string]Value{}
	for _, val := range report.Values {
		byKind[val.Kind] = val
	}
	e := byKind["EMAIL"]
	if e.Placeholder != v.Placeholder("s", "EMAIL", email) || !strings.Contains(string(out), e.Placeholder) {
		t.Fatalf("email placeholder %q is not what went upstream: %s", e.Placeholder, out)
	}
	if e.Rule != "email" || e.Head != "t" || e.Len != len([]rune(email)) || e.N != 2 || e.Action != Mask || !e.New {
		t.Errorf("email value = %+v", e)
	}
	if strings.Join(e.Paths, ",") != "messages[0].content,messages[1].content" {
		t.Errorf("email paths = %v", e.Paths)
	}
	p := byKind["PHONE"]
	if p.Action != Warn || p.Placeholder == "" || p.Head != "1" || p.New {
		t.Errorf("warned phone value = %+v", p)
	}
	if _, ok := v.Lookup("s", p.Placeholder); ok {
		t.Error("a value sent as written was put in the Vault")
	}
	if !strings.Contains(string(out), phone) {
		t.Error("the warned phone did not go upstream as written")
	}
	s := byKind["SECRET"]
	if s.Head != "ghp_" || s.Rule == "" || s.Len != len(token) {
		t.Errorf("secret value = %+v", s)
	}
	for _, val := range report.Values {
		if val.Snip == "" || !strings.Contains(val.Snip, val.Placeholder) {
			t.Errorf("%s snip %q does not hold its placeholder", val.Kind, val.Snip)
		}
		told, _ := json.Marshal(val)
		for _, original := range []string{email, phone, token} {
			if strings.Contains(string(told), original) {
				t.Errorf("%s value holds an original value: %s", val.Kind, told)
			}
		}
	}

	_, again, err := m.Mask("s", body(t, "once more "+email))
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Values) != 1 || again.Values[0].New || again.Values[0].Rule != RuleKnown && again.Values[0].Rule != "email" {
		t.Errorf("a value seen before = %+v", again.Values)
	}
}

func TestValuesOfAStoppedRequestHaveNoSnip(t *testing.T) {
	m, _ := newMasker(t)
	m = m.WithPolicy(m.detector, map[string]Action{"EMAIL": Block}).WithValues(true)
	out, report, err := m.Mask("s", body(t, "mail "+email))
	if err != nil || out != nil {
		t.Fatalf("a blocked request was sent: %s, %v", out, err)
	}
	if len(report.Values) != 1 || report.Values[0].Action != Block || report.Values[0].Snip != "" || report.Values[0].Placeholder == "" {
		t.Fatalf("blocked values = %+v", report.Values)
	}
}

func TestValuesAreOffUnlessAskedFor(t *testing.T) {
	m, _ := newMasker(t)
	_, report, err := m.Mask("s", body(t, "mail "+email))
	if err != nil || report.Total() != 1 || report.Values != nil {
		t.Fatalf("report = %+v, %v", report, err)
	}
}

func TestHint(t *testing.T) {
	for _, tc := range []struct{ kind, value, want string }{
		{"EMAIL", "test@acme-corp.cn", "t"},
		{"EMAIL", "张三@acme-corp.cn", "张"},
		{"SECRET", "sk-ant-" + strings.Repeat("x", 20), "sk-ant-"},
		{"SECRET", "sk-abc", "s"}, // the prefix would be half of it
		{"SECRET", "Bearer s3cr3t-0paque-t0ken", "Bearer "},
		{"PASSWORD", "ghp_" + strings.Repeat("x", 20), "g"}, // prefixes are for keys
		{"PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----", ""},
		{"PHONE", "12", ""},
	} {
		if got := hint(tc.kind, tc.value); got != tc.want {
			t.Errorf("hint(%s, %q) = %q, want %q", tc.kind, tc.value, got, tc.want)
		}
	}
}

func TestSnipKeepsWholeCharacters(t *testing.T) {
	text := strings.Repeat("中", 50) + "{{EMAIL_abcdefgh}}" + strings.Repeat("文", 50)
	a := strings.Index(text, "{{")
	b := a + len("{{EMAIL_abcdefgh}}")
	got := snip(text, a, b)
	if got != strings.Repeat("中", snipRunes)+"{{EMAIL_abcdefgh}}"+strings.Repeat("文", snipRunes) {
		t.Fatalf("snip = %q", got)
	}
}
