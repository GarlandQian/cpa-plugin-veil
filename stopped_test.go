package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestStoppedBodyKeepsNoText(t *testing.T) {
	cases := map[string]string{
		`{"model":"claude-sonnet-5-5","stream":true,"max_tokens":10,"system":"secret","messages":[{"role":"user","content":"secret"}]}`: `{"model":"claude-sonnet-5-5","stream":true,"messages":[]}`,
		`{"model":"gpt-5","input":"secret","instructions":"secret"}`:                                                                    `{"model":"gpt-5","input":[]}`,
		`{"model":"gemini","project":"p","request":{"contents":[{"parts":[{"text":"secret"}]}]}}`:                                       `{"model":"gemini","project":"p","request":{"contents":[]}}`,
		`{"prompt":"secret","model":"img"}`: `{"model":"img","prompt":""}`,
		`{"input":"secret"`:                 `{}`,
	}
	for body, want := range cases {
		got := string(stoppedBody([]byte(body)))
		if got != want {
			t.Errorf("stoppedBody(%s) = %s, want %s", body, got, want)
		}
		if !json.Valid([]byte(got)) || strings.Contains(got, "secret") {
			t.Errorf("bad stopped body %s", got)
		}
	}
}

func stoppedFor(t *testing.T, interceptor pluginapi.RequestInterceptor, body string) []byte {
	t.Helper()
	resp, err := interceptor.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: []byte(body)})
	if err != nil {
		t.Fatalf("a stop must not be an error, the host would send the original: %v", err)
	}
	return resp.Body
}

func TestBlockActionStopsTheRequest(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "actions:\n  email: Block\n")
	got := stoppedFor(t, interceptor, `{"model":"m","messages":[{"role":"user","content":"mail test@example.com"}]}`)
	if string(got) != `{"model":"m","messages":[]}` {
		t.Fatalf("body = %s", got)
	}
}

func TestWarnActionLetsTheValueThrough(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "actions:\n  EMAIL: warn\n")
	if got := stoppedFor(t, interceptor, `{"input":"mail test@example.com"}`); got != nil {
		t.Fatalf("warned value changed the body: %s", got)
	}
}

func TestMaskingFailureStopsTheRequest(t *testing.T) {
	p := newConfiguredInterceptor(t, "").(*veilPlugin)
	// A masker without a detector panics on the first field.
	p.masker = mask.New(nil, p.vault)
	got := stoppedFor(t, p, `{"model":"m","input":"mail test@example.com"}`)
	if string(got) != `{"model":"m","input":[]}` {
		t.Fatalf("body = %s", got)
	}
	if got := stoppedFor(t, newConfiguredInterceptor(t, ""), `{"input":"test@example.com"`); string(got) != `{}` {
		t.Fatalf("malformed JSON body = %s", got)
	}
}

func TestInvalidActionIsRejected(t *testing.T) {
	resetMasking(t)
	if _, err := buildPlugin([]byte("actions:\n  EMAIL: hide\n"), t.TempDir()); err == nil {
		t.Fatal("an unknown action must fail the config")
	}
}

func TestRestoreFailureLetsTheResponseThrough(t *testing.T) {
	p := newConfiguredInterceptor(t, "").(*veilPlugin)
	p.restorer = nil
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{Body: []byte(`{"a":1}`)})
	if err != nil || resp.Body != nil {
		t.Fatalf("resp = %s, %v", resp.Body, err)
	}
}
