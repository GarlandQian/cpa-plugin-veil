package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestDetectionOptionsFromConfig(t *testing.T) {
	dir := t.TempDir()
	extra := "[[rules]]\nid = \"internal-ticket\"\nregex = '''TKT-[0-9]{6}'''\nkeywords = [\"tkt-\"]\nkind = \"TICKET\"\n"
	if err := os.WriteFile(filepath.Join(dir, "extra.toml"), []byte(extra), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin, err := buildPlugin(t, []byte(`
rules_toml: extra.toml
disabled_rules: [phone-cn]
categories:
  ip: true
terms:
  - 烛龙
  - {term: Phoenix, any_case: true, whole_word: true}
allow: [ALICE@acme-corp.cn]
`), dir)
	if err != nil {
		t.Fatal(err)
	}
	body := string(intercept(t, plugin.Capabilities.RequestInterceptor, pluginapi.RequestInterceptRequest{
		Body: []byte(`{"input":"烛龙 PHOENIX TKT-123456 server 47.100.12.34, mail alice@acme-corp.cn, call 13800138000"}`),
	}))
	for _, want := range []string{"{{TERM_", "{{TICKET_", "public-ip-", "alice@acme-corp.cn", "13800138000"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
	for _, gone := range []string{"烛龙", "PHOENIX", "TKT-123456", "47.100.12.34"} {
		if strings.Contains(body, gone) {
			t.Errorf("%q was not masked: %s", gone, body)
		}
	}
	// The built-in gitleaks rules are still on beside rules_toml.
	if strings.Contains(string(intercept(t, plugin.Capabilities.RequestInterceptor, pluginapi.RequestInterceptRequest{
		Body: []byte(`{"input":"key AKIAIOSFODNN7EXAMPLE"}`),
	})), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("rules_toml replaced the built-in rules")
	}
}

func TestInvalidDetectionOptionsFailTheConfig(t *testing.T) {
	for _, yaml := range []string{
		"categories: {cards: true}",
		"disabled_rules: [no-such-rule]",
		"rules_toml: missing.toml",
		"terms: [' ']",
	} {

		if _, err := buildPlugin(t, []byte(yaml), t.TempDir()); err == nil {
			t.Errorf("accepted %q", yaml)
		}
	}
}
