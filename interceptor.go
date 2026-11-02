package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/jsontree"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type veilPlugin struct {
	cfg       veilConfig
	pluginDir string
	detector  *detect.Detector
	clean     *bodySet
}

var _ pluginapi.RequestInterceptor = (*veilPlugin)(nil)

func (p *veilPlugin) Identifier() string {
	return veilProvider
}

func (p *veilPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

// InterceptRequestAfterAuth redacts again because other plugins can add text
// after the before-auth pass: lower-priority before-auth interceptors and
// higher-priority after-auth interceptors both run later in the chain.
// Redaction is idempotent, so already-clean text produces no hits.
func (p *veilPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

func (p *veilPlugin) interceptRequest(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	resp := pluginapi.RequestInterceptResponse{}

	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp, nil
	}
	if len(req.Body) == 0 {
		return resp, nil
	}
	// A body one pass already left clean, such as the before-auth output the
	// after-auth pass receives, needs no second look.
	sum := sha256.Sum256(req.Body)
	if p.clean != nil && p.clean.has(sum) {
		return resp, nil
	}

	modified, hits, err := p.redactPayload(req.Body)
	if err != nil {
		pluginLog(ctx, logLevelWarn, "veil failed to process request body: "+err.Error(), map[string]any{
			"error": err.Error(),
		})
		return resp, nil
	}
	if modified == nil {
		p.clean.add(sum)
		return resp, nil
	}
	p.clean.add(sha256.Sum256(modified))

	// The host text formatter only prints a fixed set of field names, so the
	// summary is repeated in the message.
	message := fmt.Sprintf("veil redacted %d field(s): %s", len(hits), strings.Join(hits, ", "))
	pluginLog(ctx, logLevelInfo, message, map[string]any{
		"model":           req.Model,
		"source_format":   req.SourceFormat,
		"redacted_count":  len(hits),
		"redacted_fields": hits,
	})
	resp.Body = modified
	return resp, nil
}

// redactPayload returns the rewritten body (nil when nothing changed) and the
// JSON paths of the redacted fields. Non-JSON bodies pass through untouched.
func (p *veilPlugin) redactPayload(body []byte) ([]byte, []string, error) {
	doc, err := jsontree.Parse(body)
	if err != nil || doc.Root.Kind != jsontree.Object {
		return nil, nil, nil
	}
	r := &redaction{detector: p.detector, doc: doc}
	r.payload(doc.Root, "")
	if !doc.Changed() {
		return nil, nil, nil
	}
	return doc.Bytes(), r.hits, nil
}

// labels are what each Kind is redacted to.
var labels = map[detect.Kind]string{
	detect.KindEmail:    "[EMAIL]",
	detect.KindPhone:    "[PHONE]",
	detect.KindIDCard:   "[ID]",
	detect.KindBankCard: "[BANK_CARD]",
	detect.KindIP:       "[IP]",
	detect.KindSecret:   "[SECRET]",
}

// redaction walks the prompt-bearing fields of the client request formats the
// host passes to interceptors (OpenAI chat, OpenAI Responses, OpenAI image and
// video generation, Claude, Gemini and Gemini CLI). Only free-form text is rewritten; structured data such as tool
// call arguments, function responses, files and images is left untouched.
// A key that appears more than once is redacted in every occurrence.
type redaction struct {
	detector *detect.Detector
	doc      *jsontree.Doc
	hits     []string
}

func (r *redaction) payload(m *jsontree.Value, path string) {
	// messages: OpenAI chat and Claude. input: OpenAI Responses. contents: Gemini.
	for _, key := range []string{"messages", "input", "contents"} {
		r.itemsField(m, key, path)
	}
	// system: Claude. instructions: OpenAI Responses.
	for _, key := range []string{"system", "instructions"} {
		r.contentField(m, key, path)
	}
	for _, key := range []string{"systemInstruction", "system_instruction"} {
		for _, instruction := range m.All(key) {
			if instruction.Kind == jsontree.Object {
				r.item(instruction, joinPath(path, key))
			}
		}
	}
	r.promptField(m, path)
	// Gemini CLI wraps a Gemini request in a top-level "request" object.
	if path == "" {
		for _, inner := range m.All("request") {
			if inner.Kind == jsontree.Object {
				r.payload(inner, "request")
			}
		}
	}
}

func (r *redaction) itemsField(m *jsontree.Value, key, path string) {
	path = joinPath(path, key)
	for _, v := range m.All(key) {
		switch v.Kind {
		case jsontree.String:
			r.text(v, path)
		case jsontree.Array:
			for i, item := range v.Items {
				if item.Kind == jsontree.Object {
					r.item(item, fmt.Sprintf("%s[%d]", path, i))
				}
			}
		}
	}
}

// item handles a single conversation entry: an OpenAI/Claude message, an
// OpenAI Responses input item, or a Gemini content / system instruction.
func (r *redaction) item(m *jsontree.Value, path string) {
	r.contentField(m, "content", path)
	if r.typeIs(m, "function_call_output") {
		r.contentField(m, "output", path)
	}
	for _, parts := range m.All("parts") {
		if parts.Kind == jsontree.Array {
			r.parts(parts, joinPath(path, "parts"))
		}
	}
}

func (r *redaction) parts(parts *jsontree.Value, path string) {
	for i, part := range parts.Items {
		if part.Kind == jsontree.Object {
			r.part(part, fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

func (r *redaction) part(m *jsontree.Value, path string) {
	// Gemini thought parts are bound to a thoughtSignature; rewriting their
	// text would make the upstream reject the signature.
	if r.doc.IsTrue(m.Get("thought")) {
		return
	}
	r.stringField(m, "text", joinPath(path, "text"))
	if r.typeIs(m, "tool_result") {
		r.contentField(m, "content", path)
	}
}

// contentField redacts a value that is either plain text or a list of parts.
func (r *redaction) contentField(m *jsontree.Value, key, path string) {
	path = joinPath(path, key)
	for _, v := range m.All(key) {
		switch v.Kind {
		case jsontree.String:
			r.text(v, path)
		case jsontree.Array:
			r.parts(v, path)
		}
	}
}

// promptField handles the image/video generation prompt (a string or a list of
// strings). Completions requests never reach interceptors in this shape: the
// host converts them to chat completions first.
func (r *redaction) promptField(m *jsontree.Value, path string) {
	path = joinPath(path, "prompt")
	for _, v := range m.All("prompt") {
		switch v.Kind {
		case jsontree.String:
			r.text(v, path)
		case jsontree.Array:
			for i, item := range v.Items {
				r.text(item, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
}

func (r *redaction) stringField(m *jsontree.Value, key, path string) {
	for _, v := range m.All(key) {
		r.text(v, path)
	}
}

func (r *redaction) typeIs(m *jsontree.Value, want string) bool {
	got, ok := r.doc.Text(m.Get("type"))
	return ok && got == want
}

// text redacts one string value; anything else is left alone.
func (r *redaction) text(v *jsontree.Value, path string) {
	text, ok := r.doc.Text(v)
	if !ok {
		return
	}
	hits := r.detector.Detect(text)
	if len(hits) == 0 {
		return
	}
	var b strings.Builder
	prev := 0
	for _, h := range hits {
		b.WriteString(text[prev:h.Start])
		b.WriteString(labels[h.Kind])
		prev = h.End
	}
	b.WriteString(text[prev:])
	r.doc.SetString(v, b.String())
	r.hits = append(r.hits, path)
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// bodySet remembers the hashes of bodies a pass has already left clean, in
// two generations so it stays bounded.
type bodySet struct {
	mu   sync.Mutex
	cur  map[[sha256.Size]byte]struct{}
	prev map[[sha256.Size]byte]struct{}
}

const bodySetGenSize = 4096

func newBodySet() *bodySet {
	return &bodySet{cur: make(map[[sha256.Size]byte]struct{})}
}

func (s *bodySet) has(sum [sha256.Size]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cur[sum]; ok {
		return true
	}
	_, ok := s.prev[sum]
	return ok
}

func (s *bodySet) add(sum [sha256.Size]byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cur) >= bodySetGenSize {
		s.prev = s.cur
		s.cur = make(map[[sha256.Size]byte]struct{}, bodySetGenSize)
	}
	s.cur[sum] = struct{}{}
}
