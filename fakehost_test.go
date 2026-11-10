package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// hostProfile is what a CPA release does at the Host seam. Veil never asks
// which one it has: it sees the schema the Host offers.
type hostProfile struct {
	name string
	// schema is what the Host offers at plugin.register. CPA v7, which Veil
	// does not work with, offers none, gives no request IDs and has no
	// Terminate.
	schema uint32
}

var (
	hostV7 = hostProfile{name: "CPA v7"}
	hostV8 = hostProfile{name: "CPA v8", schema: 10}
)

// requestIDs numbers the requests of every fakeHost, as CPA gives each
// request an ID no other has.
var requestIDs atomic.Int64

func newRequestID() string {
	return fmt.Sprintf("request-%d", requestIDs.Add(1))
}

// fakeHost is the in-memory adapter at the Host seam, as the cgo adapter is
// the production one: it talks to Veil only in the bytes the Host sends. It
// acts on an answer as CPA does, so what a failure answer lets through shows
// in what the upstream gets.
type fakeHost struct {
	t       testing.TB
	profile hostProfile
	runtime *pluginRuntime
	schema  uint32 // what Veil registered with
}

// fakeRequest is one request going through the Host.
type fakeRequest struct {
	id       string
	headers  http.Header
	original []byte // as the client sent it
	upstream []byte // as the upstream gets it; nil when it gets nothing
	// rejected is the answer of the hook that kept the request from the
	// upstream, and with it what the client gets.
	rejected *abiRequestInterceptResponse
}

// hostOf is a CPA v8 at the seam of p, for a test that set p up itself.
func hostOf(t testing.TB, p *veilPlugin) *fakeHost {
	return &fakeHost{t: t, profile: hostV8, runtime: &pluginRuntime{plugin: p}, schema: veilSchemaVersion}
}

// seamCall is one call of a test that drives the seam by hand; a failure
// answer is its error.
func seamCall(ctx context.Context, r *pluginRuntime, method string, request []byte) ([]byte, error) {
	out := r.answer(ctx, method, request)
	var envelope abiEnvelope
	if err := json.Unmarshal(out, &envelope); err != nil {
		return nil, err
	}
	if !envelope.OK {
		return nil, errors.New(envelope.Error.Message)
	}
	return out, nil
}

func newFakeHost(t *testing.T, profile hostProfile, configure ...func(*veilConfig)) *fakeHost {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = \"fake host\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{t: t, profile: profile, runtime: &pluginRuntime{}}
	t.Cleanup(h.runtime.close)
	cfg := veilConfig{Key: strings.Repeat("42", 32), BaseDir: dir, GitleaksTOML: "rules.toml"}
	for _, change := range configure {
		change(&cfg)
	}
	register := map[string]any{"config_yaml": configBytes(t, cfg)}
	if profile.schema > 0 {
		register["schema_version"] = profile.schema
	}
	var registration abiRegistration
	if !h.result(h.call(pluginabi.MethodPluginRegister, register), &registration) {
		t.Fatalf("%s: registration failed", profile.name)
	}
	h.schema = registration.SchemaVersion
	return h
}

// call sends the Host's JSON for request over the seam.
func (h *fakeHost) call(method string, request any) abiEnvelope {
	h.t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.callRaw(method, raw)
}

func (h *fakeHost) callRaw(method string, raw []byte) abiEnvelope {
	h.t.Helper()
	var envelope abiEnvelope
	if err := json.Unmarshal(h.runtime.answer(h.t.Context(), method, raw), &envelope); err != nil {
		h.t.Fatalf("%s: the answer is no envelope: %v", method, err)
	}
	return envelope
}

// result decodes an answer into v and says whether it was one.
func (h *fakeHost) result(envelope abiEnvelope, v any) bool {
	h.t.Helper()
	if !envelope.OK {
		return false
	}
	if err := json.Unmarshal(envelope.Result, v); err != nil {
		h.t.Fatal(err)
	}
	return true
}

// requestCall is the Host's call of a request hook, with the body it has now.
func (h *fakeHost) requestCall(r *fakeRequest, body []byte) map[string]any {
	call := map[string]any{"Model": "m", "SourceFormat": "openai-response", "Headers": r.headers, "Body": body}
	if r.id != "" {
		call["RequestID"] = r.id
	}
	return call
}

// requestHook is the answer to one request hook, which a test expects to run.
func (h *fakeHost) requestHook(method string, req abiRequestInterceptRequest) abiRequestInterceptResponse {
	h.t.Helper()
	var out abiRequestInterceptResponse
	if !h.result(h.call(method, req), &out) {
		h.t.Fatalf("%s failed", method)
	}
	return out
}

// send takes a request through the request hooks, and returns it as the
// upstream gets it.
func (h *fakeHost) send(caller, body string) *fakeRequest {
	h.t.Helper()
	r := &fakeRequest{headers: bearer(caller), original: []byte(body), upstream: []byte(body)}
	if h.profile.schema > 0 {
		r.id = newRequestID()
	}
	for _, method := range []string{pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter} {
		r.upstream, r.rejected = h.acted(h.call(method, h.requestCall(r, r.upstream)), r.upstream)
		if r.rejected != nil {
			r.upstream = nil
			break
		}
	}
	return r
}

// acted is what the Host goes on with after a request hook's answer: one that
// failed leaves it the body it had, as does an answer without a body. A Host
// that has Terminate also returns the answer that refuses the request.
func (h *fakeHost) acted(envelope abiEnvelope, body []byte) ([]byte, *abiRequestInterceptResponse) {
	h.t.Helper()
	var out abiRequestInterceptResponse
	if !h.result(envelope, &out) {
		return body, nil
	}
	if len(out.Body) > 0 {
		body = out.Body
	}
	if out.Terminate && h.profile.schema > 0 {
		return body, &out
	}
	return body, nil
}

// responseCall is the Host's call of a response hook. bodies says whether the
// request bodies come with it, which Veil does not read.
func (h *fakeHost) responseCall(r *fakeRequest, bodies bool) map[string]any {
	call := map[string]any{"RequestHeaders": r.headers}
	if r.id != "" {
		call["RequestID"] = r.id
	}
	if bodies {
		call["OriginalRequest"], call["RequestBody"] = r.original, r.upstream
	}
	return call
}

// respond takes a response through the response hook, and returns it as the
// client gets it.
func (h *fakeHost) respond(r *fakeRequest, body string) string {
	h.t.Helper()
	call := h.responseCall(r, true)
	call["Body"] = []byte(body)
	var out pluginapi.ResponseInterceptResponse
	if !h.result(h.call(pluginabi.MethodResponseInterceptAfter, call), &out) || len(out.Body) == 0 {
		return body
	}
	return string(out.Body)
}

// stream takes a streamed response through the stream hook, and returns it
// as the client gets it.
func (h *fakeHost) stream(r *fakeRequest, chunks []string) string {
	h.t.Helper()
	s := h.open(r)
	for _, chunk := range chunks {
		s.send(chunk)
	}
	return s.visible()
}

// fakeStream is one response streaming through the Host a chunk at a time,
// for a test that interleaves streams or looks at the chunks.
type fakeStream struct {
	h    *fakeHost
	r    *fakeRequest
	next int
	out  []string
}

// open starts a stream with the header-init call. A plugin of Veil's schema
// gets the request bodies with that call only.
func (h *fakeHost) open(r *fakeRequest) *fakeStream {
	h.t.Helper()
	init := h.responseCall(r, true)
	init["ChunkIndex"] = pluginapi.StreamChunkHeaderInitIndex
	h.call(pluginabi.MethodResponseInterceptStreamChunk, init)
	return &fakeStream{h: h, r: r}
}

// send delivers one chunk. A hook that failed leaves it as it came.
func (s *fakeStream) send(chunk string) {
	s.h.t.Helper()
	call := s.h.responseCall(s.r, s.h.schema < veilSchemaVersion)
	call["ChunkIndex"], call["Body"] = s.next, []byte(chunk)
	s.next++
	var out pluginapi.StreamChunkInterceptResponse
	switch {
	case !s.h.result(s.h.call(pluginabi.MethodResponseInterceptStreamChunk, call), &out):
		s.out = append(s.out, chunk)
	case out.DropChunk:
	case len(out.Body) > 0:
		s.out = append(s.out, string(out.Body))
	default:
		s.out = append(s.out, chunk)
	}
}

// visible is the stream so far as the client gets it.
func (s *fakeStream) visible() string {
	return strings.Join(s.out, "")
}
