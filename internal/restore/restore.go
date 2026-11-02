// Package restore puts the original values back in place of Placeholders in
// what the model sends to the client.
package restore

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/GarlandQian/cpa-plugin-veil/internal/fields"
	"github.com/GarlandQian/cpa-plugin-veil/internal/jsontree"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// Restorer restores Placeholders from one vault.
type Restorer struct {
	vault *vault.Vault
}

// New returns a Restorer.
func New(v *vault.Vault) *Restorer {
	return &Restorer{vault: v}
}

// token matches a Placeholder as a model may write it back: the kind and
// hash in any case, with the braces doubled, single or missing and spaces
// inside them. Only a token that names a Placeholder of the Caller scope is
// restored, so ordinary text that merely looks like one is left alone.
var token = regexp.MustCompile(`(?:\{\{?[ \t]*)?([A-Za-z][A-Za-z0-9_]*)_([A-Za-z2-7]{8,52})(?:[ \t]*\}\}?)?`)

func isWord(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// Text returns text with every Placeholder of scope replaced by its value.
func (r *Restorer) Text(scope, text string) (string, bool) {
	return r.replace(scope, text, false)
}

// replace restores text; escape writes each value as it must appear inside a
// JSON string.
func (r *Restorer) replace(scope, text string, escape bool) (string, bool) {
	if !strings.Contains(text, "_") {
		return text, false
	}
	matches := token.FindAllStringSubmatchIndex(text, -1)
	if matches == nil {
		return text, false
	}
	var b strings.Builder
	prev := 0
	for _, m := range matches {
		start, end := m[0], m[1]
		if (start > 0 && isWord(text[start-1])) || (end < len(text) && isWord(text[end])) {
			continue
		}
		kind := strings.ToUpper(text[m[2]:m[3]])
		hash := strings.ToLower(text[m[4]:m[5]])
		value, ok := r.vault.Lookup(scope, "{{"+kind+"_"+hash+"}}")
		if !ok {
			continue
		}
		b.WriteString(text[prev:start])
		if escape {
			quoted := jsontree.AppendString(nil, value)
			b.Write(quoted[1 : len(quoted)-1])
		} else {
			b.WriteString(value)
		}
		prev = end
	}
	if prev == 0 {
		return text, false
	}
	b.WriteString(text[prev:])
	return b.String(), true
}

// Body returns a response body with its Placeholders restored, or nil when
// nothing changed. JSON bodies are restored field by field, leaving signed
// reasoning, identifiers and the rest of the bytes as they came; any other
// UTF-8 body is restored as plain text.
func (r *Restorer) Body(scope string, body []byte) []byte {
	if !r.vault.HasScope(scope) {
		return nil
	}
	doc, err := jsontree.Parse(body)
	if err != nil || doc.Root.Kind != jsontree.Object {
		if !utf8.Valid(body) {
			return nil
		}
		if out, ok := r.Text(scope, string(body)); ok {
			return []byte(out)
		}
		return nil
	}
	set := fields.Walk(doc)
	for _, f := range set.Fields {
		if out, ok := r.Text(scope, f.Text); ok {
			f.Doc.SetString(f.Value, out)
		}
	}
	set.Commit()
	if !doc.Changed() {
		return nil
	}
	return doc.Bytes()
}
