package main

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// recordsPage is the Masking records page. CPA serves plugin resources to
// anyone, so it holds no data: it reads the records from the Management API
// with the management key (ADR-0005).
//
//go:embed web/records.html
var recordsPage []byte

const (
	managementPrefix = "/v0/management/plugins/"
	resourcePrefix   = "/v0/resource/plugins/"
	// recordsMenu is the page's entry in the management panel's menu.
	recordsMenu = "脱敏记录"
	// previewMax is the most text a preview masks.
	previewMax = 64 << 10
	// listMax is the most records one page of the list holds.
	listMax = 200
)

type abiManagementRoute struct {
	Method      string `json:"Method,omitempty"`
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

type abiManagementRegistration struct {
	Routes    []abiManagementRoute `json:"routes"`
	Resources []abiManagementRoute `json:"resources"`
}

type abiManagementRequest struct {
	pluginapi.ManagementRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// managementRoutes are the records page and the Management API it reads.
// The routes go under the plugin's ID, which is its file's name and which
// the host gives as the end of resourceBase.
func managementRoutes(resourceBase string) abiManagementRegistration {
	id := strings.TrimPrefix(strings.TrimRight(resourceBase, "/"), strings.TrimRight(resourcePrefix, "/")+"/")
	if id == "" || strings.Contains(id, "/") {
		id = pluginName
	}
	base := managementPrefix + id
	return abiManagementRegistration{
		Routes: []abiManagementRoute{
			{Method: http.MethodGet, Path: base + "/summary"},
			{Method: http.MethodGet, Path: base + "/records"},
			{Method: http.MethodGet, Path: base + "/record"},
			{Method: http.MethodPost, Path: base + "/clear"},
			{Method: http.MethodPost, Path: base + "/preview"},
		},
		Resources: []abiManagementRoute{{
			Path:        "/index.html",
			Menu:        recordsMenu,
			Description: "Masking records of Veil: what was masked in each request, never the values themselves.",
		}},
	}
}

// handleManagement answers the records page and its Management API. No
// answer holds a value.
func (p *veilPlugin) handleManagement(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	path := strings.TrimRight(req.Path, "/")
	if strings.HasPrefix(path, resourcePrefix) {
		if req.Method == http.MethodGet && strings.HasSuffix(path, "/index.html") {
			return pluginapi.ManagementResponse{
				StatusCode: http.StatusOK,
				Headers: http.Header{
					"Content-Type":           {"text/html; charset=utf-8"},
					"Cache-Control":          {"no-store"},
					"X-Content-Type-Options": {"nosniff"},
				},
				Body: recordsPage,
			}
		}
		return jsonResponse(http.StatusNotFound, map[string]string{"error": "not found"})
	}
	name := path[strings.LastIndexByte(path, '/')+1:]
	switch req.Method + " " + name {
	case "GET summary":
		return p.summary(req)
	case "GET records":
		return p.list(req)
	case "GET record":
		return p.recordDetail(req)
	case "POST clear":
		return p.clearRecords()
	case "POST preview":
		return p.preview(req)
	}
	return jsonResponse(http.StatusNotFound, map[string]string{"error": "not found"})
}

func (p *veilPlugin) summary(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if p.records == nil {
		return jsonResponse(http.StatusOK, map[string]bool{"enabled": false})
	}
	days := 7
	if v := req.Query.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 30 {
			return badRequest("days must be a number from 1 to 30")
		}
		days = n
	}
	return jsonResponse(http.StatusOK, struct {
		Enabled bool `json:"enabled"`
		records.Summary
	}{true, p.records.Summary(days)})
}

func (p *veilPlugin) list(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if p.records == nil {
		return jsonResponse(http.StatusOK, map[string]any{"enabled": false, "records": []records.Record{}, "more": false})
	}
	q := req.Query
	var before int64
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return badRequest("before must be a record key")
		}
		before = n
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > listMax {
			return badRequest("limit must be a number from 1 to " + strconv.Itoa(listMax))
		}
		limit = n
	}
	f := records.Filter{Model: q.Get("model"), Action: q.Get("action"), Stopped: q.Get("stopped") == "1"}
	for _, kind := range strings.Split(q.Get("kind"), ",") {
		if kind = strings.TrimSpace(kind); kind != "" {
			f.Kinds = append(f.Kinds, kind)
		}
	}
	if q.Has("caller") {
		caller := q.Get("caller")
		f.Caller = &caller
	}
	list, more := p.records.List(before, limit, f)
	out := make([]listed, len(list))
	for i, r := range list {
		out[i] = listed{Record: r, Glimpse: glimpse(r)}
		out[i].Snips = nil // a record's own page shows them
	}
	return jsonResponse(http.StatusOK, map[string]any{"enabled": true, "records": out, "more": more})
}

// listed is a record as the list tells it: without its Snips, with a
// Glimpse of one.
type listed struct {
	records.Record
	// Glimpse is the Snip of the record's first value that has one, for the
	// list to show what the request was about.
	Glimpse string `json:"glimpse,omitempty"`
}

func glimpse(r records.Record) string {
	for _, v := range r.Values {
		if s := r.Snips[v.Placeholder]; s != "" {
			return s
		}
	}
	return ""
}

func (p *veilPlugin) recordDetail(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if p.records == nil {
		return jsonResponse(http.StatusNotFound, map[string]string{"error": "records are off"})
	}
	key, err := strconv.ParseInt(req.Query.Get("key"), 10, 64)
	if err != nil {
		return badRequest("key must be a record key")
	}
	r, ok := p.records.Get(key)
	if !ok {
		return jsonResponse(http.StatusNotFound, map[string]string{"error": "no such record"})
	}
	return jsonResponse(http.StatusOK, r)
}

func (p *veilPlugin) clearRecords() pluginapi.ManagementResponse {
	if p.records == nil {
		return jsonResponse(http.StatusOK, map[string]bool{"cleared": false})
	}
	if err := p.records.Clear(); err != nil {
		return jsonResponse(http.StatusInternalServerError, map[string]string{"error": "some records could not be deleted from disk"})
	}
	return jsonResponse(http.StatusOK, map[string]bool{"cleared": true})
}

// previewHit is one value a preview found, told as a record tells it.
type previewHit struct {
	Placeholder string `json:"p"`
	Kind        string `json:"kind"`
	Rule        string `json:"rule,omitempty"`
	Head        string `json:"head,omitempty"`
	Len         int    `json:"len"`
	N           int    `json:"n"`
	Action      string `json:"action"`
}

func (p *veilPlugin) preview(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	var in struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		return badRequest("the body must be {\"text\": \"...\"}")
	}
	truncated := false
	if len(in.Text) > previewMax {
		cut := previewMax
		for cut > 0 && !utf8.RuneStart(in.Text[cut]) {
			cut--
		}
		in.Text, truncated = in.Text[:cut], true
	}
	text, values := p.masker.Preview(in.Text)
	hits := make([]previewHit, 0, len(values))
	for _, v := range values {
		hits = append(hits, previewHit{v.Placeholder, v.Kind, v.Rule, v.Head, v.Len, v.N, string(v.Action)})
	}
	return jsonResponse(http.StatusOK, map[string]any{"text": text, "hits": hits, "truncated": truncated})
}

func badRequest(message string) pluginapi.ManagementResponse {
	return jsonResponse(http.StatusBadRequest, map[string]string{"error": message})
}

func jsonResponse(status int, v any) pluginapi.ManagementResponse {
	body, err := json.Marshal(v)
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"error":"could not encode the answer"}`)
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": {"application/json; charset=utf-8"}, "Cache-Control": {"no-store"}},
		Body:       body,
	}
}
