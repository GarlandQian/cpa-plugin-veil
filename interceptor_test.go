package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var emailPlaceholder = regexp.MustCompile(`\{\{EMAIL_[a-z2-7]{8}\}\}`)

// resetMasking forgets the process-wide Vault, as a restart does, and
// restores it when the test ends.
func resetMasking(t *testing.T) {
	t.Helper()
	masking.Lock()
	dir, v, m := masking.dir, masking.vault, masking.masker
	masking.dir, masking.vault, masking.masker = "", nil, nil
	masking.Unlock()
	t.Cleanup(func() {
		masking.Lock()
		masking.dir, masking.vault, masking.masker = dir, v, m
		masking.Unlock()
	})
}

// Build the public plugin with a minimal rules file so these tests exercise
// configuration and hooks without depending on optional sidecar rules.
func newConfiguredInterceptor(t *testing.T, configYAML string) pluginapi.RequestInterceptor {
	t.Helper()
	resetMasking(t)
	return buildInterceptor(t, t.TempDir(), configYAML)
}

func buildInterceptor(t *testing.T, dir, configYAML string) pluginapi.RequestInterceptor {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = \"consumer test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plugin, err := buildPlugin([]byte("gitleaks_toml: rules.toml\n"+configYAML), dir)
	if err != nil {
		t.Fatalf("buildPlugin() error = %v", err)
	}
	return plugin.Capabilities.RequestInterceptor
}

func intercept(t *testing.T, interceptor pluginapi.RequestInterceptor, req pluginapi.RequestInterceptRequest) []byte {
	t.Helper()
	resp, err := interceptor.InterceptRequestBeforeAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Body
}

func bearer(key string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+key)
	return h
}

func TestInterceptMasksWithPlaceholders(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "")
	body := intercept(t, interceptor, pluginapi.RequestInterceptRequest{
		Body: []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`),
	})
	if strings.Contains(string(body), "test@example.com") || !emailPlaceholder.Match(body) {
		t.Fatalf("expected a placeholder instead of the email: %s", body)
	}
}

func TestInterceptPassesCleanAndNonJSONBodiesThrough(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "")
	for _, body := range []string{
		`{"model":"gpt-4","messages":[{"role":"user","content":"hello world"}]}`,
		`not JSON test@example.com`,
		"",
	} {
		if got := intercept(t, interceptor, pluginapi.RequestInterceptRequest{Body: []byte(body)}); got != nil {
			t.Fatalf("expected passthrough for %q, got %s", body, got)
		}
	}
}

// Another plugin can inject text after the before-auth pass; the after-auth
// pass must catch it while leaving the already-masked text alone.
func TestInterceptAfterAuthMasksTextInjectedLater(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "")
	before := intercept(t, interceptor, pluginapi.RequestInterceptRequest{
		Body: []byte(`{"messages":[{"role":"user","content":"my email is test@example.com"}]}`),
	})
	if again, err := interceptor.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: before}); err != nil || again.Body != nil {
		t.Fatalf("after-auth changed an already-masked body: %s %v", again.Body, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(before, &payload); err != nil {
		t.Fatal(err)
	}
	payload["system"] = "memory: other@example.com"
	injected, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	after, err := interceptor.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: injected})
	if err != nil {
		t.Fatal(err)
	}
	if after.Body == nil || strings.Contains(string(after.Body), "other@example.com") {
		t.Fatalf("after-auth hook must mask injected text, got %s", after.Body)
	}
	if got := emailPlaceholder.FindAllString(string(after.Body), -1); len(got) != 2 || got[0] == got[1] {
		t.Fatalf("expected two distinct placeholders, got %v in %s", got, after.Body)
	}
}

func TestCallerScopesGetDifferentPlaceholders(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "")
	body := []byte(`{"input":"test@example.com"}`)
	a := intercept(t, interceptor, pluginapi.RequestInterceptRequest{Headers: bearer("client-a"), Body: body})
	b := intercept(t, interceptor, pluginapi.RequestInterceptRequest{Headers: bearer("client-b"), Body: body})
	again := intercept(t, interceptor, pluginapi.RequestInterceptRequest{Headers: bearer("client-a"), Body: body})
	if string(a) == string(b) {
		t.Fatalf("two API keys got the same placeholder: %s", a)
	}
	if string(a) != string(again) {
		t.Fatalf("one API key got two placeholders: %s vs %s", a, again)
	}
}

// The placeholder key lives in the plugin directory, so a restart masks the
// same value to the same placeholder.
func TestPlaceholdersSurviveRestart(t *testing.T) {
	resetMasking(t)
	dir := t.TempDir()
	body := []byte(`{"input":"test@example.com"}`)
	first := intercept(t, buildInterceptor(t, dir, ""), pluginapi.RequestInterceptRequest{Body: body})

	resetMasking(t)
	second := intercept(t, buildInterceptor(t, dir, ""), pluginapi.RequestInterceptRequest{Body: body})
	if string(first) != string(second) {
		t.Fatalf("restart changed the placeholder: %s vs %s", first, second)
	}
	if info, err := os.Stat(filepath.Join(dir, "veil.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", info, err)
	}
}

// A config reload keeps the Vault, so placeholders handed out before it still
// restore after it.
func TestReloadKeepsTheVault(t *testing.T) {
	resetMasking(t)
	dir := t.TempDir()
	first := buildInterceptor(t, dir, "").(*veilPlugin)
	intercept(t, first, pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"test@example.com"}`)})
	second := buildInterceptor(t, dir, "skip_models: [other]").(*veilPlugin)
	if second.vault != first.vault || second.vault.Len() == 0 {
		t.Fatal("reload dropped the vault")
	}
}

func TestInterceptRequest_SkippedModel(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "skip_models: [' GPT-4 ']\nskip_formats: [' OPENAI ']")
	body := []byte(`{"input":"test@example.com"}`)
	for _, req := range []pluginapi.RequestInterceptRequest{
		{Model: "gpt-4", Body: body},
		{Model: "upstream-model", RequestedModel: "gpt-4", Body: body},
		{SourceFormat: "openai", Body: body},
	} {
		before, err := interceptor.InterceptRequestBeforeAuth(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		after, err := interceptor.InterceptRequestAfterAuth(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if before.Body != nil || after.Body != nil {
			t.Fatalf("skip config must preserve request body: before=%s after=%s", before.Body, after.Body)
		}
	}
}

func TestInterceptMasksSecrets(t *testing.T) {
	resetMasking(t)
	plugin, err := buildPlugin(nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := intercept(t, plugin.Capabilities.RequestInterceptor, pluginapi.RequestInterceptRequest{
		Body: []byte(`{"messages":[{"role":"user","content":"my api key is AKIAIOSFODNN7EXAMPLE"}]}`),
	})
	if strings.Contains(string(body), "AKIAIOSFODNN7EXAMPLE") || !strings.Contains(string(body), "{{SECRET_") {
		t.Fatalf("AWS key should be masked: %s", body)
	}
}

func TestConfigShouldSkip(t *testing.T) {
	cfg := veilConfig{
		SkipModels:  []string{"gpt-4", "claude-3"},
		SkipFormats: []string{"openai"},
	}
	if !cfg.shouldSkip("gpt-4", "", "") {
		t.Fatal("should skip gpt-4")
	}
	if !cfg.shouldSkip("upstream-model", "claude-3", "") {
		t.Fatal("should skip requested claude-3")
	}
	if !cfg.shouldSkip("", "", "openai") {
		t.Fatal("should skip openai format")
	}
	if cfg.shouldSkip("gemini-pro", "", "anthropic") {
		t.Fatal("should not skip unknown model/format")
	}
}

func TestConfigParse(t *testing.T) {
	raw := `
skip_models:
  - gpt-4
skip_formats:
  - openai
`
	cfg, removed, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if len(cfg.SkipModels) != 1 || cfg.SkipModels[0] != "gpt-4" {
		t.Fatalf("skip_models = %v, want [gpt-4]", cfg.SkipModels)
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %v, want none", removed)
	}
}

// Configs written for privacyfilter still load; the removed label fields are
// reported instead of failing registration.
func TestConfigParseReportsRemovedFields(t *testing.T) {
	raw := "replacement: '[HIDDEN]'\nreplacement_labels:\n  email: '<MAIL>'\nskip_models: [gpt-4]\n"
	cfg, removed, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if !reflect.DeepEqual(removed, []string{"replacement", "replacement_labels"}) {
		t.Fatalf("removed = %v", removed)
	}
	if len(cfg.SkipModels) != 1 {
		t.Fatalf("skip_models = %v, want [gpt-4]", cfg.SkipModels)
	}
	body := intercept(t, newConfiguredInterceptor(t, raw), pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"test@example.com"}`)})
	if !emailPlaceholder.Match(body) {
		t.Fatalf("expected a placeholder: %s", body)
	}
}

func TestRegistrationCapabilityJSON(t *testing.T) {
	raw, err := json.Marshal(newABIRegistration(pluginMetadata()).Capabilities)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, name := range []string{`"request_interceptor":true`, `"response_interceptor":true`} {
		if !strings.Contains(string(raw), name) {
			t.Fatalf("expected %s in JSON: %s", name, raw)
		}
	}
}

// The loop an agent runs: the request is masked, the model answers with the
// placeholder (also in a tool call), the answer is restored for the client,
// and the next turn re-sends that answer, which masks to the same
// placeholder again.
func TestRoundTripThroughTheABI(t *testing.T) {
	resetMasking(t)
	dir := t.TempDir()
	raw, err := handleVeilRegister(context.Background(), "plugin.register", registerRequest(t, dir, ""))
	if err != nil {
		t.Fatal(err)
	}
	if reg := decodeRegistration(t, raw); !reg.Capabilities.RequestInterceptor || !reg.Capabilities.ResponseInterceptor {
		t.Fatalf("capabilities = %+v", reg.Capabilities)
	}
	call := func(method string, req any) json.RawMessage {
		t.Helper()
		payload, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		out, err := handleVeilABIMethod(context.Background(), method, payload)
		if err != nil {
			t.Fatal(err)
		}
		var envelope abiEnvelope
		if err := json.Unmarshal(out, &envelope); err != nil || !envelope.OK {
			t.Fatalf("envelope %s: %v", out, err)
		}
		return envelope.Result
	}
	headers := bearer("client-a")
	request := []byte(`{"messages":[{"role":"user","content":"mail test@example.com"}]}`)
	var masked pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(call("request.intercept_before", abiRequestInterceptRequest{RequestInterceptRequest: pluginapi.RequestInterceptRequest{Headers: headers, Body: request}}), &masked); err != nil {
		t.Fatal(err)
	}
	p := emailPlaceholder.FindString(string(masked.Body))
	if p == "" {
		t.Fatalf("request not masked: %s", masked.Body)
	}

	answer := []byte(`{"content":[{"type":"text","text":"I will mail ` + p + `"},{"type":"tool_use","id":"t1","name":"send","input":{"to":"` + p + `"}}]}`)
	var restored pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(call("response.intercept_after", abiResponseInterceptRequest{ResponseInterceptRequest: pluginapi.ResponseInterceptRequest{RequestHeaders: headers, Body: answer}}), &restored); err != nil {
		t.Fatal(err)
	}
	want := `{"content":[{"type":"text","text":"I will mail test@example.com"},{"type":"tool_use","id":"t1","name":"send","input":{"to":"test@example.com"}}]}`
	if string(restored.Body) != want {
		t.Fatalf("restored = %s", restored.Body)
	}

	other := pluginapi.ResponseInterceptRequest{RequestHeaders: bearer("client-b"), Body: answer}
	var foreign pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(call("response.intercept_after", abiResponseInterceptRequest{ResponseInterceptRequest: other}), &foreign); err != nil {
		t.Fatal(err)
	}
	if foreign.Body != nil {
		t.Fatalf("another client got the value back: %s", foreign.Body)
	}

	next := []byte(`{"messages":[{"role":"user","content":"mail test@example.com"},{"role":"assistant","content":[{"type":"text","text":"I will mail test@example.com"},{"type":"tool_use","id":"t1","name":"send","input":{"to":"test@example.com"}}]}]}`)
	var again pluginapi.RequestInterceptResponse
	if err := json.Unmarshal(call("request.intercept_before", abiRequestInterceptRequest{RequestInterceptRequest: pluginapi.RequestInterceptRequest{Headers: headers, Body: next}}), &again); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(again.Body), "test@example.com") || strings.Count(string(again.Body), p) != 3 {
		t.Fatalf("history did not mask back to the same placeholder: %s", again.Body)
	}
}
