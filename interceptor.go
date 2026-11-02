package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"
	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type veilPlugin struct {
	cfg       veilConfig
	pluginDir string
	masker    *mask.Masker
	restorer  *restore.Restorer
	vault     *vault.Vault
	streams   *streamRegistry
	clean     *bodySet
}

var (
	_ pluginapi.RequestInterceptor     = (*veilPlugin)(nil)
	_ pluginapi.ResponseInterceptor    = (*veilPlugin)(nil)
	_ pluginapi.StreamChunkInterceptor = (*veilPlugin)(nil)
)

func (p *veilPlugin) Identifier() string {
	return veilProvider
}

func (p *veilPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

// InterceptRequestAfterAuth masks again because other plugins can add text
// after the before-auth pass: lower-priority before-auth interceptors and
// higher-priority after-auth interceptors both run later in the chain.
// Masking is idempotent, so an already-masked body produces no hits.
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
	scope := vault.ScopeOf(req.Headers)
	// A body one pass already left masked, such as the before-auth output the
	// after-auth pass receives, needs no second look.
	sum := bodySum(scope, req.Body)
	if p.clean.has(sum) {
		return resp, nil
	}

	masked, report, err := p.masker.Mask(scope, req.Body)
	if err != nil {
		pluginLog(ctx, logLevelWarn, "veil failed to process request body: "+err.Error(), map[string]any{
			"error": err.Error(),
		})
		return resp, nil
	}
	if masked == nil {
		p.clean.add(sum)
		return resp, nil
	}
	p.clean.add(bodySum(scope, masked))

	// The host text formatter only prints a fixed set of field names, so the
	// summary is repeated in the message.
	message := fmt.Sprintf("veil masked %d value(s) (%s) in %d field(s): %s", report.Total(), kindSummary(report.Counts), len(report.Paths), strings.Join(report.Paths, ", "))
	pluginLog(ctx, logLevelInfo, message, map[string]any{
		"model":         req.Model,
		"source_format": req.SourceFormat,
		"masked_count":  report.Total(),
		"masked_kinds":  report.Counts,
		"masked_fields": report.Paths,
	})
	resp.Body = masked
	return resp, nil
}

// InterceptResponse restores the Placeholders of a non-streaming response,
// looking them up in the Caller scope of the request that caused it.
func (p *veilPlugin) InterceptResponse(ctx context.Context, req pluginapi.ResponseInterceptRequest) (pluginapi.ResponseInterceptResponse, error) {
	resp := pluginapi.ResponseInterceptResponse{}
	if len(req.Body) == 0 {
		return resp, nil
	}
	resp.Body = p.restorer.Body(vault.ScopeOf(req.RequestHeaders), req.Body)
	return resp, nil
}

// InterceptStreamChunk restores the Placeholders of a streamed response. The
// header-only call that opens a stream registers it; each chunk then goes
// through that stream's Held tail state.
func (p *veilPlugin) InterceptStreamChunk(ctx context.Context, req pluginapi.StreamChunkInterceptRequest) (pluginapi.StreamChunkInterceptResponse, error) {
	resp := pluginapi.StreamChunkInterceptResponse{}
	scope := vault.ScopeOf(req.RequestHeaders)
	key := bodySum(scope, req.RequestBody)
	if req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex {
		if p.vault.HasScope(scope) {
			p.streams.start(key, func(hold bool) *restore.Stream { return p.restorer.NewStream(scope, hold) })
		}
		return resp, nil
	}
	if len(req.Body) == 0 {
		return resp, nil
	}
	entry := p.streams.take(key, req.ChunkIndex)
	var stream *restore.Stream
	switch {
	case entry != nil:
		stream = entry.stream
	case p.vault.HasScope(scope):
		stream = p.restorer.NewStream(scope, false)
	default:
		return resp, nil
	}
	out, done := stream.Chunk(req.Body)
	if done && entry != nil {
		p.streams.end(key, entry)
	}
	switch {
	case len(out) == 0:
		resp.DropChunk = true
	case !bytes.Equal(out, req.Body):
		resp.Body = out
	}
	return resp, nil
}

// kindSummary lists the counts per Kind, such as "EMAIL=2, SECRET=1".
func kindSummary(counts map[string]int) string {
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	parts := make([]string, len(kinds))
	for i, kind := range kinds {
		parts[i] = fmt.Sprintf("%s=%d", kind, counts[kind])
	}
	return strings.Join(parts, ", ")
}

func bodySum(scope string, body []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write(body)
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// bodySet remembers the hashes of bodies a pass has already left masked, in
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
	if s == nil {
		return false
	}
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
