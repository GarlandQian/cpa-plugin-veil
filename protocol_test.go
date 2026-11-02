package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestHostCallbackIDContext(t *testing.T) {
	if got := hostCallbackIDFromContext(nil); got != "" {
		t.Fatalf("nil context id = %q", got)
	}
	if got := hostCallbackIDFromContext(withHostCallbackID(nil, " ")); got != "" {
		t.Fatalf("blank id should be ignored, got %q", got)
	}
	if got := hostCallbackIDFromContext(withHostCallbackID(context.Background(), "cb-1")); got != "cb-1" {
		t.Fatalf("id = %q, want cb-1", got)
	}
}

func TestPluginLogFallsBackWithoutHost(t *testing.T) {
	veilABIState.Lock()
	previous := veilABIState.host
	veilABIState.host = nil
	veilABIState.Unlock()
	t.Cleanup(func() {
		veilABIState.Lock()
		veilABIState.host = previous
		veilABIState.Unlock()
	})
	if hostLog("", logLevelInfo, "message", nil) {
		t.Fatal("hostLog must report failure without an attached host")
	}
	pluginLog(nil, logLevelInfo, "fallback", map[string]any{"k": "v"})
}

func TestNewFilterErrorNamesRulesSource(t *testing.T) {
	invalid := []byte("[[rules]\n")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "gitleaks.toml"), invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "custom.toml"), invalid, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		cfg  veilConfig
		want string
	}{
		{"sidecar", veilConfig{}, "sidecar rules file"},
		{"configured", veilConfig{GitleaksTOML: "custom.toml"}, "gitleaks_toml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newDetector(dir, tc.cfg)
			if err == nil {
				t.Fatal("expected invalid rules to fail")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q should mention %q", err, tc.want)
			}
			if tc.name == "sidecar" && strings.Contains(err.Error(), "gitleaks_toml") {
				t.Fatalf("sidecar error must not blame gitleaks_toml: %q", err)
			}
		})
	}
}

func registerRequest(t *testing.T, dir, configYAML string) []byte {
	t.Helper()
	raw, err := json.Marshal(abiLifecycleRequest{ConfigYAML: []byte(configYAML), PluginDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeRegistration(t *testing.T, raw []byte) abiRegistration {
	t.Helper()
	var envelope abiEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("expected ok envelope, got %s", raw)
	}
	var registration abiRegistration
	if err := json.Unmarshal(envelope.Result, &registration); err != nil {
		t.Fatal(err)
	}
	return registration
}

func TestReconfigureKeepsPreviousConfigOnInvalidConfig(t *testing.T) {
	veilABIState.Lock()
	previous := veilABIState.plugin
	veilABIState.plugin = nil
	veilABIState.Unlock()
	t.Cleanup(func() {
		veilABIState.Lock()
		veilABIState.plugin = previous
		veilABIState.Unlock()
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = \"reconfigure test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := handleVeilRegister(ctx, pluginabi.MethodPluginRegister, registerRequest(t, dir, "gitleaks_toml: rules.toml\nskip_models: 123")); err == nil {
		t.Fatal("initial register must reject invalid config")
	}

	raw, err := handleVeilRegister(ctx, pluginabi.MethodPluginRegister, registerRequest(t, dir, "gitleaks_toml: rules.toml\nskip_models: [first]"))
	if err != nil {
		t.Fatalf("register error = %v", err)
	}
	registration := decodeRegistration(t, raw)
	if !registration.Capabilities.RequestInterceptor || registration.Metadata.Name != pluginName {
		t.Fatalf("unexpected registration %+v", registration)
	}
	veilABIState.RLock()
	valid := veilABIState.plugin
	veilABIState.RUnlock()

	raw, err = handleVeilRegister(ctx, pluginabi.MethodPluginReconfigure, registerRequest(t, dir, "gitleaks_toml: rules.toml\nskip_formats: true"))
	if err != nil {
		t.Fatalf("reconfigure with invalid config must keep serving, got %v", err)
	}
	registration = decodeRegistration(t, raw)
	if !registration.Capabilities.RequestInterceptor || registration.Metadata.Version != pluginVersion {
		t.Fatalf("unexpected registration %+v", registration)
	}
	veilABIState.RLock()
	current := veilABIState.plugin
	veilABIState.RUnlock()
	if current != valid {
		t.Fatal("invalid reconfigure must keep the previous plugin instance")
	}
	resp, err := current.InterceptRequestBeforeAuth(ctx, pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"test@example.com"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !emailPlaceholder.Match(resp.Body) {
		t.Fatalf("expected a placeholder: %s", resp.Body)
	}

	if _, err = handleVeilRegister(ctx, pluginabi.MethodPluginReconfigure, registerRequest(t, dir, "gitleaks_toml: rules.toml\nskip_models: [second]")); err != nil {
		t.Fatalf("valid reconfigure error = %v", err)
	}
	veilABIState.RLock()
	current = veilABIState.plugin
	veilABIState.RUnlock()
	if current == valid {
		t.Fatal("valid reconfigure must replace the plugin instance")
	}
}

// Only masked strings are re-encoded: key order, number spelling, escapes
// and HTML characters elsewhere in the body reach the upstream as sent.
func TestMaskingKeepsUntouchedBytes(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "")
	body := `{"seed":12345678901234567890,"z":1,"a":"<b>&é",` + "\n" + `"messages":[{"role":"user","content":"mail test@example.com"}]}`
	resp, err := interceptor.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	want := regexp.MustCompile("^" + regexp.QuoteMeta(`{"seed":12345678901234567890,"z":1,"a":"<b>&é",`+"\n"+`"messages":[{"role":"user","content":"mail `) + `\{\{EMAIL_[a-z2-7]{8}\}\}` + regexp.QuoteMeta(`"}]}`) + "$")
	if !want.Match(resp.Body) {
		t.Fatalf("body = %s", resp.Body)
	}
}
