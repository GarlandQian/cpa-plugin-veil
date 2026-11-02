// Package fields finds the strings of a request or response that carry what
// people and tools wrote, as opposed to identifiers, protocol fields, binary
// data and signed reasoning. Masking and restoring walk the same fields.
package fields

import (
	"fmt"
	"strings"

	"github.com/GarlandQian/cpa-plugin-veil/internal/jsontree"
)

// mode is how a subtree of the document is walked.
type mode uint8

const (
	// conversation: every string is a Field except under keptKeys.
	conversation mode = iota
	// tool: a tool's own arguments or result, whose keys belong to the tool,
	// so every string is a Field whatever its key.
	tool
	// definition: request settings and tool definitions; only descriptions
	// are free text.
	definition
)

// keptKeys hold identifiers, signatures, binary data, names and protocol
// fields: rewriting them would break the request without hiding anything a
// person wrote.
var keptKeys = map[string]bool{
	"signature": true, "encrypted_content": true, "data": true, "file_data": true,
	"thoughtSignature": true, "thought_signature": true,
	"id": true, "prompt_cache_key": true, "cachedContent": true, "cached_content": true,
	"name": true, "namespace": true, "server_label": true, "server_name": true,
	"model": true, "type": true, "role": true, "object": true, "event": true, "status": true,
	"stop_reason": true, "finish_reason": true, "cache_control": true, "service_tier": true,
	"media_type": true, "mime_type": true, "mimeType": true, "url": true, "image_url": true,
	"reasoning_effort": true, "effort": true,
}

// definitionKeys are top-level request fields that configure the model or
// define tools rather than carry the conversation.
var definitionKeys = map[string]bool{
	"tools": true, "tool_choice": true, "functions": true, "function_call": true,
	"toolConfig": true, "tool_config": true, "response_format": true, "text": true,
	"reasoning": true, "thinking": true, "include": true, "output_format": true, "output_config": true,
	"generationConfig": true, "generation_config": true, "safetySettings": true, "safety_settings": true,
	"stream_options": true, "client_metadata": true, "additional_tools": true, "tool_search_output": true,
	"mcp_servers": true,
}

// toolUseTypes are the Claude content blocks whose input is a tool's
// arguments.
var toolUseTypes = map[string]bool{"tool_use": true, "server_tool_use": true, "mcp_tool_use": true}

// sealedTypes are reasoning blocks bound to a provider signature: Claude
// thinking and redacted thinking, and OpenAI Responses reasoning items.
// Gemini marks its sealed parts with thought: true instead.
var sealedTypes = map[string]bool{"thinking": true, "redacted_thinking": true, "reasoning": true}

// minFieldLen is the shortest string worth looking at: no sensitive value or
// Placeholder is shorter.
const minFieldLen = 4

// Field is one string to mask or restore.
type Field struct {
	Doc   *jsontree.Doc
	Value *jsontree.Value
	Text  string
	Path  string
}

// Nested is a string holding JSON, such as OpenAI's tool call arguments,
// whose own strings are Fields of Inner.
type Nested struct {
	Outer *jsontree.Doc
	Value *jsontree.Value
	Inner *jsontree.Doc
}

// Set is the Fields of a document and the JSON strings nested in it.
type Set struct {
	Fields []*Field
	Nested []*Nested
}

// Walk finds the Fields of doc, whose root is an object, in document order.
func Walk(doc *jsontree.Doc) *Set {
	w := &walker{}
	w.object(doc, doc.Root, "", "", conversation, true)
	return &Set{Fields: w.fields, Nested: w.nested}
}

// Commit writes every changed nested document back into its outer string,
// innermost first, since an argument string can sit inside another.
func (s *Set) Commit() {
	for i := len(s.Nested) - 1; i >= 0; i-- {
		n := s.Nested[i]
		if n.Inner.Changed() {
			n.Outer.SetString(n.Value, string(n.Inner.Bytes()))
		}
	}
}

type walker struct {
	fields []*Field
	nested []*Nested
}

func (w *walker) value(doc *jsontree.Doc, v *jsontree.Value, path, key string, m mode) {
	switch v.Kind {
	case jsontree.String:
		if m != definition {
			w.text(doc, v, path)
		}
	case jsontree.Array:
		for i, item := range v.Items {
			w.value(doc, item, fmt.Sprintf("%s[%d]", path, i), key, m)
		}
	case jsontree.Object:
		w.object(doc, v, path, key, m, false)
	}
}

// object walks the members of o, which is the value of key in its parent.
// isRoot marks the request object itself, whose definitionKeys are settings.
func (w *walker) object(doc *jsontree.Doc, o *jsontree.Value, path, key string, m mode, isRoot bool) {
	typ, _ := doc.Text(o.Get("type"))
	if m == conversation && (sealedTypes[typ] || doc.IsTrue(o.Get("thought"))) {
		return
	}
	for _, member := range o.Members {
		k, v := member.Key, member.Value
		p := joinPath(path, k)
		switch m {
		case definition:
			if k == "description" {
				if v.Kind == jsontree.String {
					w.text(doc, v, p)
				}
				continue
			}
			w.value(doc, v, p, k, definition)
		case tool:
			w.value(doc, v, p, k, tool)
		default:
			switch {
			case isRoot && definitionKeys[k] && (k != "text" || v.Kind == jsontree.Object):
				w.value(doc, v, p, k, definition)
			case isRoot && k == "request" && v.Kind == jsontree.Object:
				// Gemini CLI wraps a Gemini request in a top-level request.
				w.object(doc, v, p, k, conversation, true)
			case k == "data" && typ == "text":
				// A Claude document with a plain-text source keeps its text
				// in data.
				w.value(doc, v, p, k, conversation)
			case kept(k):
			case k == "input" && toolUseTypes[typ],
				k == "args" && (key == "functionCall" || key == "function_call"),
				k == "response" && (key == "functionResponse" || key == "function_response"):
				w.value(doc, v, p, k, tool)
			case k == "arguments" && v.Kind == jsontree.String:
				w.arguments(doc, v, p)
			default:
				w.value(doc, v, p, k, conversation)
			}
		}
	}
}

func kept(key string) bool {
	return keptKeys[key] || strings.HasSuffix(key, "_id") || strings.HasSuffix(key, "Id") || strings.HasSuffix(key, "_ids")
}

// arguments handles a tool call's arguments, which OpenAI sends as JSON
// inside a string: their strings are Fields one by one, so the result stays
// valid JSON. Arguments that are not JSON are one plain-text Field.
func (w *walker) arguments(doc *jsontree.Doc, v *jsontree.Value, path string) {
	text, ok := doc.Text(v)
	if !ok {
		return
	}
	inner, err := jsontree.Parse([]byte(text))
	if err != nil || (inner.Root.Kind != jsontree.Object && inner.Root.Kind != jsontree.Array) {
		w.text(doc, v, path)
		return
	}
	w.nested = append(w.nested, &Nested{Outer: doc, Value: v, Inner: inner})
	sub := &walker{}
	sub.value(inner, inner.Root, path, "", tool)
	w.fields = append(w.fields, sub.fields...)
	w.nested = append(w.nested, sub.nested...)
}

func (w *walker) text(doc *jsontree.Doc, v *jsontree.Value, path string) {
	text, ok := doc.Text(v)
	if !ok || len(text) < minFieldLen || strings.HasPrefix(text, "data:") {
		return
	}
	w.fields = append(w.fields, &Field{Doc: doc, Value: v, Text: text, Path: path})
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
