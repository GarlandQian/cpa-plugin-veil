package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func configBytes(t *testing.T, cfg veilConfig) []byte {
	t.Helper()
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func configuredPlugin(t *testing.T, dir string, cfg veilConfig) *veilPlugin {
	t.Helper()
	return reconfigurePlugin(t, &pluginInstance{}, dir, cfg)
}

func reconfigurePlugin(t *testing.T, i *pluginInstance, dir string, cfg veilConfig) *veilPlugin {
	t.Helper()
	t.Cleanup(i.close)
	p, err := i.configure(configBytes(t, cfg), dir)
	if err != nil {
		t.Fatal(err)
	}
	return p.Capabilities.RequestInterceptor.(*veilPlugin)
}

func shadowDir(t *testing.T, pid string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cliproxy-pluginhost", "pid-"+pid)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func capturePluginLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	output := log.StandardLogger().Out
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(output) })
	return &buf
}

func TestConfiguredKeySurvivesShadowCopyRestart(t *testing.T) {
	logs := capturePluginLogs(t)
	cfg := veilConfig{
		Key:        hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		Categories: map[string]bool{"home": true, "ip": true},
	}
	req := pluginapi.RequestInterceptRequest{
		Headers: bearer("test-client"),
		Body:    []byte(`{"input":"mail test@acme-corp.cn, /Users/alice/project, server 47.100.12.34"}`),
	}
	firstDir, secondDir := shadowDir(t, "100"), shadowDir(t, "200")
	first := intercept(t, configuredPlugin(t, firstDir, cfg), req)
	if !emailPlaceholder.Match(first) || !strings.Contains(string(first), "public-ip-") || strings.Contains(string(first), "/Users/alice/") {
		t.Fatalf("expected a Placeholder and Stand-ins: %s", first)
	}

	restarted := configuredPlugin(t, secondDir, cfg)
	placeholder := emailPlaceholder.FindString(string(first))
	scope := vault.ScopeOf(req.Headers)
	if _, ok := restarted.vault.Lookup(scope, placeholder); ok {
		t.Fatal("persisting a key must not be mistaken for persisting the Vault")
	}
	second := intercept(t, restarted, req)
	if !bytes.Equal(first, second) {
		t.Fatalf("shadow-copy restart changed masked history: %s vs %s", first, second)
	}
	if got, ok := restarted.vault.Lookup(scope, placeholder); !ok || got != "test@acme-corp.cn" {
		t.Fatal("re-sent original history did not rebuild the old Placeholder mapping")
	}
	for _, dir := range []string{firstDir, secondDir} {
		if _, err := os.Stat(filepath.Join(dir, vault.KeyFile)); !os.IsNotExist(err) {
			t.Fatalf("a shadow directory must not hold veil.key: %v", err)
		}
	}
	if strings.Contains(logs.String(), cfg.Key) {
		t.Fatal("the configured key was logged")
	}
}

func TestShadowCopyWithoutKeyWarnsAndKeepsReloadStable(t *testing.T) {
	logs := capturePluginLogs(t)
	dir := shadowDir(t, "100")
	req := pluginapi.RequestInterceptRequest{Headers: bearer("test-client"), Body: []byte(`{"input":"test@acme-corp.cn"}`)}
	instance := &pluginInstance{}
	first := intercept(t, reconfigurePlugin(t, instance, dir, veilConfig{}), req)
	reloaded := intercept(t, reconfigurePlugin(t, instance, dir, veilConfig{}), req)
	if !bytes.Equal(first, reloaded) {
		t.Fatal("reload rotated the in-memory key")
	}
	if !strings.Contains(logs.String(), "in-memory key") || !strings.Contains(logs.String(), "plugins.configs.veil.key") {
		t.Fatal("missing actionable warning about the nonpersistent key")
	}

	second := intercept(t, configuredPlugin(t, dir, veilConfig{}), req)
	if bytes.Equal(first, second) {
		t.Fatal("a shadow file or the client API key was used for persistence")
	}
	if _, err := os.Stat(filepath.Join(dir, vault.KeyFile)); !os.IsNotExist(err) {
		t.Fatalf("shadow copy created veil.key: %v", err)
	}
}

func TestShadowCopyWithKeyLogsOneNoticeAndNoWarning(t *testing.T) {
	logs := capturePluginLogs(t)
	dir := shadowDir(t, "100")
	cfg := veilConfig{Key: hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32))}
	instance := &pluginInstance{}
	reconfigurePlugin(t, instance, dir, cfg)
	reconfigurePlugin(t, instance, dir, cfg) // a reload
	if strings.Contains(logs.String(), "level=warning") || strings.Contains(logs.String(), "level=error") {
		t.Fatalf("a configured key and the embedded rules need no warning: %s", logs)
	}
	if n := strings.Count(logs.String(), "shadow copy"); n != 1 {
		t.Fatalf("the shadow copy notice was logged %d times", n)
	}
}

func TestLegacyKeyMigratesToConfigWithoutChangingPlaceholders(t *testing.T) {
	dir := t.TempDir()
	req := pluginapi.RequestInterceptRequest{Headers: bearer("test-client"), Body: []byte(`{"input":"test@acme-corp.cn"}`)}
	first := intercept(t, configuredPlugin(t, dir, veilConfig{}), req)
	key, err := os.ReadFile(filepath.Join(dir, vault.KeyFile))
	if err != nil {
		t.Fatal(err)
	}

	second := intercept(t, configuredPlugin(t, shadowDir(t, "200"), veilConfig{Key: string(key)}), req)
	if !bytes.Equal(first, second) {
		t.Fatal("copying veil.key into key changed Placeholders")
	}
	// Keeping the old directory through base_dir is also a lossless migration.

	third := intercept(t, configuredPlugin(t, shadowDir(t, "300"), veilConfig{BaseDir: dir}), req)
	if !bytes.Equal(first, third) {
		t.Fatal("base_dir did not reuse the legacy key")
	}
}

func TestShadowRuleFilesUseExplicitBaseOrAbsolutePaths(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	dir := shadowDir(t, "100")
	original := filepath.Join(cwd, "original")
	if err := os.MkdirAll(filepath.Join(original, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	mainRules := "[[rules]]\nid = \"main-code\"\nregex = '''MAIN-[0-9]{6}'''\n"
	extraRules := "[[rules]]\nid = \"extra-code\"\nregex = '''EXTRA-[0-9]{6}'''\nkind = \"EXTRA\"\n"
	for path, raw := range map[string]string{
		filepath.Join(original, "rules", "gitleaks.toml"): mainRules,
		filepath.Join(original, "extra.toml"):             extraRules,
		filepath.Join(cwd, "extra.toml"):                  "invalid TOML [",
	} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	key := hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	for _, field := range []string{"gitleaks_toml", "rules_toml"} {
		t.Run(field+" requires a base", func(t *testing.T) {
			_, err := buildPlugin(t, []byte("key: '"+key+"'\n"+field+": extra.toml\n"), dir)
			if err == nil || !strings.Contains(err.Error(), "base_dir") || !strings.Contains(err.Error(), field) {
				t.Fatalf("relative rule path should require base_dir: %v", err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		cfg  veilConfig
	}{
		{"sidecar", veilConfig{Key: key, BaseDir: "original", RulesTOML: "extra.toml"}},
		{"relative", veilConfig{Key: key, BaseDir: original, GitleaksTOML: "rules/gitleaks.toml", RulesTOML: "extra.toml"}},
		{"absolute", veilConfig{Key: key, GitleaksTOML: filepath.Join(original, "rules", "gitleaks.toml"), RulesTOML: filepath.Join(original, "extra.toml")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := configuredPlugin(t, dir, tc.cfg)
			body := intercept(t, p, pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"MAIN-123456 EXTRA-123456"}`)})
			if !strings.Contains(string(body), "{{SECRET_") || !strings.Contains(string(body), "{{EXTRA_") {
				t.Fatalf("rule files did not load: %s", body)
			}
		})
	}
	// An unrelated sidecar in the working directory must never replace the
	// embedded rules merely because the original plugin directory is unknown.
	if err := os.Mkdir(filepath.Join(cwd, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "rules", "gitleaks.toml"), []byte("invalid TOML ["), 0o600); err != nil {
		t.Fatal(err)
	}

	configuredPlugin(t, dir, veilConfig{Key: key})
	for _, base := range []string{dir, cwd, original} {
		if _, err := os.Stat(filepath.Join(base, vault.KeyFile)); !os.IsNotExist(err) {
			t.Fatalf("configured key unexpectedly wrote veil.key: %v", err)
		}
	}
}

func TestShadowDirectoryRecognitionAndOverride(t *testing.T) {
	for path, want := range map[string]bool{
		filepath.Join("tmp", "cliproxy-pluginhost", "pid-123"):      true,
		filepath.Join("tmp", "cliproxy-pluginhost", "pid-0"):        false,
		filepath.Join("tmp", "cliproxy-pluginhost", "pid-abc"):      false,
		filepath.Join("tmp", "cliproxy-pluginhost", "pid-123-copy"): false,
		filepath.Join("tmp", "my-cliproxy-pluginhost", "pid-123"):   false,
		filepath.Join("tmp", "cliproxy-pluginhost", "pid-123", "x"): false,
	} {
		if got := isShadowPluginDir(path); got != want {
			t.Errorf("isShadowPluginDir(%q) = %v, want %v", path, got, want)
		}
	}
	dir := shadowDir(t, "123")
	if _, err := (&pluginInstance{}).resolvePluginDir(dir, ""); err == nil {
		t.Fatal("base_dir accepted a temporary shadow directory")
	}
	if _, err := (&pluginInstance{}).resolvePluginDir(filepath.Join(t.TempDir(), "missing"), ""); err == nil {
		t.Fatal("base_dir accepted a missing directory")
	}
	// The host-supplied original path takes precedence over library inference.
	original := t.TempDir()
	got, err := (&pluginInstance{}).resolvePluginDir("", original)
	want, _ := filepath.EvalSymlinks(original)
	if err != nil || got != want {
		t.Fatalf("host directory = %q, %v", got, err)
	}
}

func TestInvalidConfiguredKeyDoesNotExposeItsValue(t *testing.T) {
	for _, value := range []string{"do-not-log-this", strings.Repeat("z", 64), "[do-not-log-this]", "{secret: do-not-log-this}"} {
		if _, _, err := parseConfig([]byte("key: " + value)); err == nil {
			t.Fatal("invalid key was accepted")
		} else if strings.Contains(err.Error(), "do-not-log-this") || strings.Contains(err.Error(), strings.Repeat("z", 64)) {
			t.Fatal("invalid key appeared in a config error")
		}
	}
}

func TestKeyChangesOnReloadKeepThePreviousPlugin(t *testing.T) {
	logs := capturePluginLogs(t)
	runtime := &pluginRuntime{}
	defer runtime.close()
	dir := t.TempDir()
	ctx := context.Background()
	if _, err := runtime.register(ctx, pluginabi.MethodPluginRegister, registerRequest(t, dir, "")); err != nil {
		t.Fatal(err)
	}
	first := runtime.plugin
	req := pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"test@acme-corp.cn"}`)}
	masked := intercept(t, first, req)
	key, err := os.ReadFile(filepath.Join(dir, vault.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	// Moving the very same key into config can be done without a restart.
	if _, err := runtime.register(ctx, pluginabi.MethodPluginReconfigure, registerRequest(t, dir, string(configBytes(t, veilConfig{Key: string(key)})))); err != nil {
		t.Fatal(err)
	}
	valid := runtime.plugin
	if valid.vault != first.vault || valid.streams != first.streams || valid.vault.Len() == 0 {
		t.Fatal("same-key migration lost the Vault or active streams")
	}
	for _, cfg := range []veilConfig{
		{Key: hex.EncodeToString(bytes.Repeat([]byte{0x43}, 32))},
		{Key: "do-not-log-this"},
		{}, // Removing an explicit key also changes its source.
	} {
		if _, err := runtime.register(ctx, pluginabi.MethodPluginReconfigure, registerRequest(t, dir, string(configBytes(t, cfg)))); err != nil {
			t.Fatal(err)
		}
		if runtime.plugin != valid {
			t.Fatal("key change replaced the working plugin")
		}
	}
	if !bytes.Equal(masked, intercept(t, valid, req)) {
		t.Fatal("rejected key changes altered masking")
	}
	if !strings.Contains(logs.String(), "requires a CPA restart") || strings.Contains(logs.String(), "do-not-log-this") || strings.Contains(logs.String(), strings.TrimSpace(string(key))) {
		t.Fatal("reload warning was missing or exposed a key")
	}
	if !strings.Contains(logs.String(), "CPA v7 config disable does not") {
		t.Fatal("reload warning incorrectly promises a new instance after v7 config disable")
	}
}
