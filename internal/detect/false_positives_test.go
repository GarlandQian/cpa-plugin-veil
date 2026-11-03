package detect

import (
	"testing"
)

// TestFalsePositivesFromAgentRequests are what one coding agent's request
// had masked on 2026-11-03 that held nothing sensitive, as its record showed
// them, and values like them that are sensitive.
func TestFalsePositivesFromAgentRequests(t *testing.T) {
	d, err := newFromPath(gitleaksRules)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		text string
		want []string // the values found, in order; none for a false positive
	}{
		// generic-api-key took a whole match, its key's name too, and an English word as the key
		{"prose after api", "This is code. `JSON.stringify()` is not shell escaping, interpolating its output into a shell command can preserve it.", nil},
		{"env assignment", "export OPENAI_API_KEY=sk-proj-Qw8rT2yU6iO0pA4sD7fG1hJ5kL9zX3cV && ls", []string{"sk-proj-Qw8rT2yU6iO0pA4sD7fG1hJ5kL9zX3cV"}},
		{"quoted token", `token = "aZ8kQ2mX7pL4vN9rT3wB6yC1" 用这个调一下接口`, []string{"aZ8kQ2mX7pL4vN9rT3wB6yC1"}},

		// high-entropy took a file's name for a key, a word of the name for its context
		{"adr file", "- ADR: `docs/adr/0015-windows-credential-manager-login.md`。", nil},
		{"adr link", "不把凭据放入普通配置。见 [ADR-0015](./docs/adr/0015-windows-credential-manager-login.md) | 用户", nil},
		{"escaped path", `参数规避迁移。\ndocs/adr/0015-windows-credential-manager-login.md:5:与仅会话保存相比`, nil},
		{"docs link", `see [encrypted secrets](https://help.github.com/en/actions/automating-your-workflow-with-github-actions/creating-and-using-encrypted-secrets)\n# Default: ${{ github.token }}`, nil},
		{"bearer with a slash", "Authorization: Bearer abc/DEF123ghi456JKL789mnoPQ==", []string{"Bearer abc/DEF123ghi456JKL789mnoPQ=="}},

		// context-secret took code for a value, and a type
		{"call", `const myToken = gate.issue(\"wt-a\");\n    try {`, nil},
		{"bare call", "const token = gate.issue();\n\n  assert.equal(gate.accept(token, {", nil},
		{"type annotation", "captureIncoming: (worktreeId: string) => IncomingToken | null;\n  clearIncoming: (token: IncomingToken) => void;\n  let token: IncomingToken;", nil},
		{"member", "const token = config.sessionToken;", nil},
		{"password word", "我的密码：786kih2x", []string{"786kih2x"}},
		{"password", "password: Tr0ub4dor&3", []string{"Tr0ub4dor&3"}},

		// an escape's letter before an address
		{"git remote in JSON text", `{"original_token_count":26,"output":"origin\tgit@github.com:GarlandQian/Revia.git (fetch)\norigin\tgit@github.com:GarlandQian/Revia.git (push)"}`, nil},
		{"email after an escape", `owner:\tlin.wei@acme-corp.cn`, []string{"lin.wei@acme-corp.cn"}},

		// a value where the line ends in an escape
		{"empty env in a log", `2026-11-02T13:49:24.8267140Z TAURI_SIGNING_PRIVATE_KEY: \nBuild Windows x64 installer and portable\tVerify portable dependencies\t2026-11-02T13:49:24.8268564Z TAURI_SIGNING_PRIVATE_KEY_PASSWORD: \nBuild Windows x64 installer`, nil},

		// a fixture's URL
		{"fixture url", `printf '%s\\n' 'https://fixture-user:S3cretPw9x@example.invalid/o/r' >&2`, nil},
		{"real url", "postgres://admin:S3cretPw9x@db.acme-corp.cn/app", []string{"S3cretPw9x"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, h := range d.Detect(tt.text) {
				got = append(got, tt.text[h.Start:h.End]+" ("+h.Rule+")")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("found %q, want %q", got, tt.want)
			}
			for i, h := range d.Detect(tt.text) {
				if v := tt.text[h.Start:h.End]; v != tt.want[i] {
					t.Errorf("found %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestDisabledRulesTakeTheBuiltInFallbacks(t *testing.T) {
	text := `token = "aZ8kQ2mX7pL4vN9rT3wB6yC1"` + "\nsecret key AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/"
	d, err := New(nil, Options{DisabledRules: []string{"context-secret", "high-entropy"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range d.Detect(text) {
		if h.Rule == "context-secret" || h.Rule == "high-entropy" {
			t.Errorf("a disabled rule found %q", text[h.Start:h.End])
		}
	}
}

func TestGitleaksAllowlists(t *testing.T) {
	rules := []byte(`
[allowlist]
paths = ['''\.png$''']
regexes = ['''^dummy''']
stopwords = ["example"]

[[rules]]
id = "word"
regex = '''word=([A-Za-z0-9]{8,})'''
[[rules.allowlists]]
regexTarget = "line"
regexes = ['''(?i)fixture''']
[[rules.allowlists]]
condition = "AND"
regexes = ['''^Zz''']
stopwords = ["test"]
[[rules.allowlists]]
condition = "AND"
paths = ['''\.go$''']
regexes = ['''.''']
`)
	d, err := New(rules, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for text, want := range map[string]string{
		"word=Abc12345xyz":                "Abc12345xyz", // the group, not the match
		"word=dummy12345":                 "",            // the file's regex
		"word=myexample1":                 "",            // the file's stop word
		"fixture: word=Abc12345xyz":       "",            // the line
		"word=Zz12345678":                 "Zz12345678",  // AND: the regex but no stop word
		"word=Zztest5678":                 "",            // AND: both
		"other line\nword=Qq12345678 end": "Qq12345678",  // AND over paths never matches
	} {
		hits := d.Detect(text)
		got := ""
		if len(hits) > 0 {
			got = text[hits[0].Start:hits[0].End]
		}
		if got != want {
			t.Errorf("%q: found %q, want %q", text, got, want)
		}
	}
}
