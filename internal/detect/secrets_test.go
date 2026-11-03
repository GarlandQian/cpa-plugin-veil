package detect

import (
	"strings"
	"testing"
)

func TestHasStrongSecretContext(t *testing.T) {
	candidate := "key" + strings.Repeat("A", 20)
	tests := []struct {
		name   string
		prefix string
		token  string
		want   bool
	}{
		{"reported_33_30", strings.Repeat(".", 26) + "api ", candidate, true},
		{"short_overlap", "api ", candidate, true},
		{"lookback_overlap", strings.Repeat(".", 80) + "api ", candidate, true},
		{"unicode_prefix", "请使用 api ", candidate, true},
		{"tab_overlap", "api\t", candidate, true},
		{"access_key_overlap", "access ", candidate, true},
		{"keyword_at_start", "", "token=" + strings.Repeat("A", 20), true},
		{"keyword_inside", "", strings.Repeat("A", 20) + "token", false},
		{"keyword_in_a_file_name", "ADR: `", "docs/adr/0015-windows-credential-manager-login", false},
		{"adjacent_keyword", "密码", candidate, true},
		{"assignment", "token: '", candidate, true},
		{"authorization", "Authorization: Basic ", candidate, true},
		{"path_keyword", "api_key.example.com/", candidate, false},
		{"unrelated_keyword", "token unrelated ", candidate, false},
		{"outside_lookback", "token" + strings.Repeat(" ", contextLookback), candidate, false},
		{"no_keyword", "", candidate, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := tt.prefix + tt.token
			if got := hasStrongSecretContext(text, len(tt.prefix), len(text)); got != tt.want {
				t.Errorf("hasStrongSecretContext(%q) = %v, want %v", text, got, tt.want)
			}
		})
	}
}

func TestRedactOverlappingSecretContext(t *testing.T) {
	for _, rules := range []string{"", gitleaksRules} {
		name := "builtin"
		if rules != "" {
			name = "gitleaks"
		}
		t.Run(name, func(t *testing.T) {
			f, err := newFromPath(rules)
			if err != nil {
				t.Fatal(err)
			}
			for _, prefix := range []string{"", strings.Repeat(".", 26), strings.Repeat(".", 80)} {
				text := prefix + "api key" + strings.Repeat("A", 20)
				result := f.Redact(text)
				if result.Hit || result.Redacted != text {
					t.Errorf("low-entropy text should be unchanged: input=%q result=%+v", text, result)
				}
			}

			text := "api keyabcDEF1234567890/xyzABC4567890=="
			result := f.Redact(text)
			if !result.Hit || strings.Contains(result.Redacted, "abcDEF1234567890/xyzABC4567890==") {
				t.Errorf("overlapping context must still redact a secret containing '/': %+v", result)
			}
		})
	}
}
