package main

import (
	"github.com/GarlandQian/cpa-plugin-veil/internal/jsontree"
)

// stoppedBody is what a Stopped request sends instead of its body: the model
// and stream settings, and every conversation field emptied, which every
// provider rejects as a bad request before any inference. Nothing of the
// original text goes out.
//
// The host offers a plugin no way to fail a request itself, and routes the
// request before interceptors run, so the request still reaches the upstream.
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
