package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"
	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
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
	streams   *streamRestorer
	clean     *bodySet
	// records is nil when records are off. links still observes requests so
	// a late unidentified response cannot take a record after re-enabling.
	records *records.Store
	links   *recordLinks
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
	return p.interceptRequest(ctx, req, "", false)
}

// InterceptRequestAfterAuth masks again because other plugins can add text
// after the before-auth pass: lower-priority before-auth interceptors and
// higher-priority after-auth interceptors both run later in the chain.
// Masking is idempotent, so an already-masked body produces no hits.
func (p *veilPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req, "", true)
}

// interceptRequest masks a request. It never returns an error: the host would
// send the original body upstream. A request Veil cannot mask, or one holding
// a Kind whose Action is block, becomes a Stopped request instead.
func (p *veilPlugin) interceptRequest(ctx context.Context, req pluginapi.RequestInterceptRequest, requestID string, afterAuth bool) (resp pluginapi.RequestInterceptResponse, _ error) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			p.record(req, mask.Report{}, records.StoppedError, start)
			resp = p.stop(ctx, req, fmt.Sprintf("masking failed: %v", r))
		}
	}()

	if len(req.Body) == 0 {
		return resp, nil
	}
	scope := vault.ScopeOf(req.Headers)
	// A body one pass already left masked, such as the before-auth output the
	// after-auth pass receives, needs no second look.
	sum := bodySum(scope, req.Body)
	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) || p.clean.has(sum) {
		if !afterAuth && p.links != nil {
			p.links.put(scope, requestID, sum, records.Ref{})
		}
		return resp, nil
	}

	masked, report, err := p.masker.Mask(scope, req.Body)
	if err != nil {
		stopped := records.StoppedError
		if errors.Is(err, mask.ErrMalformed) {
			stopped = records.StoppedMalformed
		}
		p.record(req, report, stopped, start)
		return p.stop(ctx, req, "masking failed: "+err.Error()), nil
	}
	if len(report.Blocked) > 0 {
		p.record(req, report, records.StoppedBlock, start)
		return p.stop(ctx, req, fmt.Sprintf("it holds %s in %s, whose action is block", kindSummary(report.Blocked), strings.Join(report.BlockedPaths, ", "))), nil
	}
	if len(report.Warned) > 0 {
		pluginLog(ctx, logLevelWarn, fmt.Sprintf("veil let %d value(s) (%s) through unmasked in %d field(s): %s", total(report.Warned), kindSummary(report.Warned), len(report.WarnedPaths), strings.Join(report.WarnedPaths, ", ")), map[string]any{
			"model":         req.Model,
			"source_format": req.SourceFormat,
			"warned_kinds":  report.Warned,
			"warned_fields": report.WarnedPaths,
		})
	}
	key, recorded := p.record(req, report, "", start)
	if masked == nil {
		p.clean.add(sum)
		if p.links != nil && (recorded || !afterAuth) {
			p.links.put(scope, requestID, sum, key)
		}
		return resp, nil
	}
	maskedSum := bodySum(scope, masked)
	p.clean.add(maskedSum)
	if p.links != nil {
		p.links.put(scope, requestID, maskedSum, key)
	}

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

// record keeps a Masking record of a request that had a value or did not
// reach the upstream; stopped says why it did not. It returns the record's
// key, if it kept one.
func (p *veilPlugin) record(req pluginapi.RequestInterceptRequest, report mask.Report, stopped string, start time.Time) (records.Ref, bool) {
	if p.records == nil || (len(report.Values) == 0 && stopped == "") {
		return records.Ref{}, false
	}
	r := records.Record{
		Time:    start,
		Caller:  vault.ScopeOf(req.Headers),
		Model:   req.Model,
		Format:  req.SourceFormat,
		Stopped: stopped,
		Took:    time.Since(start).Microseconds(),
		Values:  make([]records.Value, 0, len(report.Values)),
	}
	for _, v := range report.Values {
		r.N += v.N
		r.Values = append(r.Values, records.Value{
			Placeholder: v.Placeholder,
			Kind:        v.Kind,
			Rule:        v.Rule,
			Head:        v.Head,
			Len:         v.Len,
			N:           v.N,
			Action:      string(v.Action),
			Paths:       v.Paths,
			New:         v.New,
		})
		if v.Snip != "" {
			if r.Snips == nil {
				r.Snips = map[string]string{}
			}
			r.Snips[v.Placeholder] = v.Snip
		}
	}
	return p.records.Add(r)
}

// recordOf consumes the response's association even when recording has since
// been disabled. Request IDs take precedence over the legacy body fallback.
func (p *veilPlugin) recordOf(scope, requestID string, bodies ...[]byte) (records.Ref, bool) {
	if p.links == nil {
		return records.Ref{}, false
	}
	ref, ok := p.links.take(scope, requestID, bodies...)
	return ref, ok && p.records != nil
}

// restored adds to a Masking record what its response put back.
func (p *veilPlugin) restored(key records.Ref, t *restore.Tally) {
	p.records.Restore(key, t.Back, t.Unrestored)
}

// stop turns a request into a Stopped request and says why in the log.
func (p *veilPlugin) stop(ctx context.Context, req pluginapi.RequestInterceptRequest, reason string) pluginapi.RequestInterceptResponse {
	pluginLog(ctx, logLevelError, "veil stopped a request, the upstream will reject it: "+reason, map[string]any{
		"model":         req.Model,
		"source_format": req.SourceFormat,
	})
	return pluginapi.RequestInterceptResponse{Body: stoppedBody(req.Body)}
}

// InterceptResponse restores the Placeholders of a non-streaming response,
// looking them up in the Caller scope of the request that caused it. If
// restoring fails, the response goes through with its Placeholders.
func (p *veilPlugin) InterceptResponse(ctx context.Context, req pluginapi.ResponseInterceptRequest) (pluginapi.ResponseInterceptResponse, error) {
	return p.interceptResponse(ctx, req, "")
}

func (p *veilPlugin) interceptResponse(ctx context.Context, req pluginapi.ResponseInterceptRequest, requestID string) (resp pluginapi.ResponseInterceptResponse, _ error) {
	defer func() {
		if r := recover(); r != nil {
			resp = pluginapi.ResponseInterceptResponse{}
			pluginLog(ctx, logLevelError, fmt.Sprintf("veil failed to restore a response: %v", r), nil)
		}
	}()
	if len(req.Body) == 0 {
		return resp, nil
	}
	scope := vault.ScopeOf(req.RequestHeaders)
	key, recorded := p.recordOf(scope, requestID, req.OriginalRequest, req.RequestBody)
	var tally *restore.Tally
	if recorded {
		tally = &restore.Tally{}
	}
	resp.Body = p.restorer.BodyTally(scope, req.Body, tally)
	if recorded {
		p.restored(key, tally)
	}
	return resp, nil
}

// InterceptStreamChunk restores the Placeholders of a streamed response. The
// header-only call that opens a stream registers it; each chunk then goes
// through that stream's Held tail state.
func (p *veilPlugin) InterceptStreamChunk(ctx context.Context, req pluginapi.StreamChunkInterceptRequest) (pluginapi.StreamChunkInterceptResponse, error) {
	return p.interceptStreamChunk(ctx, req, "")
}

// interceptStreamChunk restores a chunk of the stream of the request the
// host knows by requestID, or, where it gives none (CPA v7), by its body.
// Only the header-init call is sure to have the request bodies: on CPA v8
// the payload chunks come without them.
func (p *veilPlugin) interceptStreamChunk(ctx context.Context, req pluginapi.StreamChunkInterceptRequest, requestID string) (resp pluginapi.StreamChunkInterceptResponse, _ error) {
	defer func() {
		if r := recover(); r != nil {
			resp = pluginapi.StreamChunkInterceptResponse{}
			pluginLog(ctx, logLevelError, fmt.Sprintf("veil failed to restore a stream chunk: %v", r), nil)
		}
	}()
	scope := vault.ScopeOf(req.RequestHeaders)
	init := req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex
	var finish func(*restore.Tally)
	if init {
		if record, ok := p.recordOf(scope, requestID, req.OriginalRequest, req.RequestBody); ok {
			finish = func(t *restore.Tally) { p.restored(record, t) }
		}
	}
	out := p.streams.chunk(streamCall{scope: scope, requestID: requestID, requestBody: req.RequestBody, body: req.Body, index: req.ChunkIndex, init: init}, finish)
	if init || len(req.Body) == 0 {
		return resp, nil
	}
	switch {
	case len(out) == 0:
		resp.DropChunk = true
	case !bytes.Equal(out, req.Body):
		resp.Body = out
	}
	return resp, nil
}

func total(counts map[string]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
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
