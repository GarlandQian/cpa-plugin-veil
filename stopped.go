package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/GarlandQian/cpa-plugin-veil/internal/jsontree"
)

// stoppedBody is what a Stopped request sends instead of its body: the model
// and stream settings, and every conversation field emptied, which every
// provider rejects as a bad request before any inference. Nothing of the
// original text goes out.
//
// CPA v7 offers a plugin no way to fail a request itself, and routes the
// request before interceptors run, so there it still reaches the upstream.
func stoppedBody(body []byte) []byte {
	out := []byte{'{'}
	add := func(key string, raw []byte) {
		if len(out) > 1 {
			out = append(out, ',')
		}
		out = jsontree.AppendString(out, key)
		out = append(out, ':')
		out = append(out, raw...)
	}
	doc, err := jsontree.Parse(body)
	if err != nil || doc.Root.Kind != jsontree.Object {
		return append(out, '}')
	}
	for _, key := range []string{"model", "project"} {
		if v := doc.Root.Get(key); v != nil && v.Kind == jsontree.String {
			add(key, []byte(doc.Raw(v)))
		}
	}
	if v := doc.Root.Get("stream"); v != nil && v.Kind == jsontree.Bool {
		add("stream", []byte(doc.Raw(v)))
	}
	for _, key := range []string{"messages", "input", "contents"} {
		if doc.Root.Get(key) != nil {
			add(key, []byte("[]"))
		}
	}
	if doc.Root.Get("prompt") != nil {
		add("prompt", []byte(`""`))
	}
	if v := doc.Root.Get("request"); v != nil && v.Kind == jsontree.Object {
		add("request", []byte(`{"contents":[]}`))
	}
	return append(out, '}')
}

// stoppedStatus is what a client gets for a Stopped request on a Host that
// can refuse one. Clients do not retry it, as they would a 5xx on a request
// that can only fail again.
const stoppedStatus = http.StatusForbidden

// stoppedUnreadable is what a client is told of a request Veil could not
// handle. The reason goes to the log, where it cannot quote the request.
const stoppedUnreadable = "Veil could not process this request, so it was not sent. See the CLIProxyAPI log."

// stoppedBlocked is what a client is told of a request holding Kinds with the
// block Action: their names, for the caller to know what to take out, and
// neither the values nor where they were.
func stoppedBlocked(kinds map[string]int) string {
	names := make([]string, 0, len(kinds))
	for kind := range kinds {
		names = append(names, kind)
	}
	sort.Strings(names)
	return "Veil stopped this request: it holds " + strings.Join(names, ", ") + ", which this proxy is set to block."
}

// stoppedAnswer is a request hook's answer for a Stopped request, of a client
// speaking format. A Host that can refuse a request goes by Terminate; one
// that cannot sends the rewritten body, which the upstream rejects. Both are
// always there: Veil does not ask which Host it has, and a Host that stopped
// honoring Terminate would still send nothing of the request.
func stoppedAnswer(format string, body []byte, told string) abiRequestInterceptResponse {
	return abiRequestInterceptResponse{
		Body:            stoppedBody(body),
		Terminate:       true,
		StatusCode:      stoppedStatus,
		ResponseHeaders: http.Header{"Content-Type": {"application/json"}},
		ResponseBody:    stoppedError(format, told),
	}
}

// stoppedError is an error in the shape the client's protocol has, so that
// the client shows message and not a failure it cannot read.
func stoppedError(format, message string) []byte {
	var shape map[string]any
	switch {
	case strings.HasPrefix(format, "claude"):
		shape = map[string]any{"type": "error", "error": map[string]any{"type": "permission_error", "message": message}}
	case strings.HasPrefix(format, "gemini"):
		shape = map[string]any{"error": map[string]any{"code": stoppedStatus, "message": message, "status": "PERMISSION_DENIED"}}
	default:
		shape = map[string]any{"error": map[string]any{"message": message, "type": "invalid_request_error", "code": "veil_stopped"}}
	}
	raw, _ := json.Marshal(shape)
	return raw
}
