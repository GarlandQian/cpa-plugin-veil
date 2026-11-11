package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"
	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/roundtrip"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type veilPlugin struct {
	cfg       veilConfig
	pluginDir string
	masker    *mask.Masker
	vault     *vault.Vault
	// trips follows each request to the end of its response. The instance's
	// config views share it, as they do the Vault.
	trips *roundtrip.Trips
	// records is nil when records are off.
	records *records.Store
	// hostTooOld says why every request of this Host is a Stopped request. It
	// is empty on a Host Veil works with.
	hostTooOld string
}

// interceptRequest masks a request in one Pass. A request Veil cannot mask, or
// one holding a Kind whose Action is block, becomes a Stopped request. The Host
// hands a request over before it picks a credential and again after, for each
// credential it tries: other plugins can add text in between, lower-priority
// before-auth interceptors and higher-priority after-auth interceptors both
// running later in the chain. Masking is idempotent, so an already-masked body
// produces no hits, and all the Passes keep one Masking record.
func (p *veilPlugin) interceptRequest(ctx context.Context, req abiRequestInterceptRequest, beforeAuth bool) (resp abiRequestInterceptResponse) {
	start := time.Now()
	var pass *roundtrip.Pass
	keep := func(report mask.Report, stopped string) {
		if pass == nil {
			pass = p.passOf(req, false)
		}
		pass.Keep(p.records, recordOf(req, report, stopped, start))
	}
	defer func() {
		if r := recover(); r != nil {
			keep(mask.Report{}, records.StoppedError)
			resp = stop(ctx, req, fmt.Sprintf("masking failed: %v", r), stoppedUnreadable)
		}
	}()

	if len(req.Body) == 0 {
		return resp
	}
	pass = p.passOf(req, beforeAuth)
	if p.hostTooOld != "" {
		// A Host without Terminate hands the emptied body to the next Pass,
		// which has nothing left to stop.
		if bytes.Equal(req.Body, stoppedBody(req.Body)) {
			return resp
		}
		keep(mask.Report{}, records.StoppedError)
		return stop(ctx, req, p.hostTooOld, stoppedHostTooOld)
	}
	// A body an earlier Pass of the request left, such as the before-auth
	// output the after-auth Pass receives, needs no second look.
	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) || pass.Left(req.Body) {
		return resp
	}

	scope := vault.ScopeOf(req.Headers)
	masked, report, err := p.masker.Mask(scope, req.Body)
	if err != nil {
		stopped := records.StoppedError
		if errors.Is(err, mask.ErrMalformed) {
			stopped = records.StoppedMalformed
		}
		keep(report, stopped)
		return stop(ctx, req, "masking failed: "+err.Error(), stoppedUnreadable)
	}
	if len(report.Blocked) > 0 {
		keep(report, records.StoppedBlock)
		return stop(ctx, req, fmt.Sprintf("it holds %s in %s, whose action is block", kindSummary(report.Blocked), strings.Join(report.BlockedPaths, ", ")), stoppedBlocked(report.Blocked))
	}
	if len(report.Warned) > 0 {
		pluginLog(ctx, logLevelWarn, fmt.Sprintf("veil let %d value(s) (%s) through unmasked in %d field(s): %s", total(report.Warned), kindSummary(report.Warned), len(report.WarnedPaths), strings.Join(report.WarnedPaths, ", ")), map[string]any{
			"model":         req.Model,
			"source_format": req.SourceFormat,
			"warned_kinds":  report.Warned,
			"warned_fields": report.WarnedPaths,
		})
	}
	keep(report, "")
	pass.Leave(masked)
	if masked == nil {
		return resp
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
	return resp
}

// passOf is the Pass a request hook's call is, in the Round trip of its
// request.
func (p *veilPlugin) passOf(req abiRequestInterceptRequest, beforeAuth bool) *roundtrip.Pass {
	return p.trips.Pass(vault.ScopeOf(req.Headers), req.RequestID, beforeAuth)
}

// keepStopped keeps a Masking record of a request stopped before Veil could
// look at it.
func (p *veilPlugin) keepStopped(req abiRequestInterceptRequest, start time.Time) {
	p.passOf(req, false).Keep(p.records, recordOf(req, mask.Report{}, records.StoppedError, start))
}

// recordOf is what a Masking record says of one Pass: the values it found,
// and why it stopped the request, if it did.
func recordOf(req abiRequestInterceptRequest, report mask.Report, stopped string, start time.Time) records.Record {
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
	return r
}

// stop turns a request into a Stopped request. The log gets reason in full;
// told is all the client gets.
func stop(ctx context.Context, req abiRequestInterceptRequest, reason, told string) abiRequestInterceptResponse {
	pluginLog(ctx, logLevelError, "veil stopped a request: "+reason, map[string]any{
		"model":         req.Model,
		"source_format": req.SourceFormat,
	})
	return stoppedAnswer(req.SourceFormat, req.Body, told)
}

// interceptResponse restores the Placeholders of a non-streaming response,
// looking them up in the Caller scope of the request that caused it. If
// restoring fails, the response goes through with its Placeholders.
func (p *veilPlugin) interceptResponse(ctx context.Context, req abiResponseInterceptRequest) (resp pluginapi.ResponseInterceptResponse) {
	defer func() {
		if r := recover(); r != nil {
			resp = pluginapi.ResponseInterceptResponse{}
			pluginLog(ctx, logLevelError, fmt.Sprintf("veil failed to restore a response: %v", r), nil)
		}
	}()
	if len(req.Body) == 0 {
		return resp
	}
	resp.Body = p.trips.Respond(vault.ScopeOf(req.RequestHeaders), req.RequestID, req.Body)
	return resp
}

// interceptStreamChunk restores a chunk of a streamed response. The Host
// opens a stream with a header-only call, and then hands over its chunks.
func (p *veilPlugin) interceptStreamChunk(ctx context.Context, req abiStreamChunkInterceptRequest) (resp pluginapi.StreamChunkInterceptResponse) {
	defer func() {
		if r := recover(); r != nil {
			resp = pluginapi.StreamChunkInterceptResponse{}
			pluginLog(ctx, logLevelError, fmt.Sprintf("veil failed to restore a stream chunk: %v", r), nil)
		}
	}()
	scope := vault.ScopeOf(req.RequestHeaders)
	if req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex {
		p.trips.Open(scope, req.RequestID)
		return resp
	}
	out := p.trips.Chunk(scope, req.RequestID, req.ChunkIndex, req.Body)
	if len(req.Body) == 0 {
		return resp
	}
	switch {
	case len(out) == 0:
		resp.DropChunk = true
	case !bytes.Equal(out, req.Body):
		resp.Body = out
	}
	return resp
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
