package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"
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

func stoppedFor(t *testing.T, interceptor *veilPlugin, body string) []byte {
	t.Helper()
	return intercept(t, interceptor, abiRequestInterceptRequest{Body: []byte(body)})
}

func TestBlockActionStopsTheRequest(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "actions:\n  email: Block\n")
	got := stoppedFor(t, interceptor, `{"model":"m","messages":[{"role":"user","content":"mail test@acme-corp.cn"}]}`)
	if string(got) != `{"model":"m","messages":[]}` {
		t.Fatalf("body = %s", got)
	}
}

func TestWarnActionLetsTheValueThrough(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "actions:\n  EMAIL: warn\n")
	if got := stoppedFor(t, interceptor, `{"input":"mail test@acme-corp.cn"}`); got != nil {
		t.Fatalf("warned value changed the body: %s", got)
	}
}

func TestMaskingFailureStopsTheRequest(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	// A masker without a detector panics on the first field.
	p.masker = mask.New(nil, p.vault)
	got := stoppedFor(t, p, `{"model":"m","input":"mail test@acme-corp.cn"}`)
	if string(got) != `{"model":"m","input":[]}` {
		t.Fatalf("body = %s", got)
	}
	if got := stoppedFor(t, newConfiguredInterceptor(t, ""), `{"input":"test@acme-corp.cn"`); string(got) != `{}` {
		t.Fatalf("malformed JSON body = %s", got)
	}
}

func TestInvalidActionIsRejected(t *testing.T) {
	if _, err := buildPlugin(t, []byte("actions:\n  EMAIL: hide\n"), t.TempDir()); err == nil {
		t.Fatal("an unknown action must fail the config")
	}
}

func TestRestoreFailureLetsTheResponseThrough(t *testing.T) {
	p := newConfiguredInterceptor(t, "")
	p.restorer = nil
	if resp := respondTo(t, p, abiResponseInterceptRequest{Body: []byte(`{"a":1}`)}); resp != nil {
		t.Fatalf("resp = %s", resp)
	}
}
