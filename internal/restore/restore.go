// Package restore puts the original values back in place of Placeholders in
// what the model sends to the client.
package restore

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
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

// standInWord matches what may be a Stand-in, as a whole word: a public
// IP address's or a user name's, in any case.
var standInWord = regexp.MustCompile(`(?i)\bpublic-ip-[a-z]{8}\b|\b[a-z]{8}\b`)

func isWord(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// Text returns text with every Placeholder of scope replaced by its value.
func (r *Restorer) Text(scope, text string) (string, bool) {
	return r.replace(scope, text, false, nil)
}

// replace restores text, counting into t; escape writes each value as it must
// appear inside a JSON string.
func (r *Restorer) replace(scope, text string, escape bool, t *Tally) (string, bool) {
	out, placeholders := r.placeholders(scope, text, escape, t)
	out, standIns := r.standIns(scope, out, escape, t)
	return out, placeholders || standIns
}

// standIns restores the Stand-ins of scope in text, in any case and only as
// whole words.
func (r *Restorer) standIns(scope, text string, escape bool, t *Tally) (string, bool) {
	if len(text) < 8 || !r.vault.HasStandIns(scope) {
		return text, false
	}
	changed := false
	out := standInWord.ReplaceAllStringFunc(text, func(word string) string {
		value, ok := r.vault.Lookup(scope, strings.ToLower(word))
		if !ok || !r.vault.IsStandIn(scope, word) {
			return word
		}
		changed = true
		t.back(strings.ToLower(word))
		if escape {
			quoted := jsontree.AppendString(nil, value)
			return string(quoted[1 : len(quoted)-1])
		}
		return value
	})
	return out, changed
}

// placeholders restores the Placeholders of scope in text.
func (r *Restorer) placeholders(scope, text string, escape bool, t *Tally) (string, bool) {
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
		// A brace marks where a Placeholder starts or ends, so a word may
		// touch it there: masking itself leaves one against the text around
		// a value ({{SECRET_…}}Mobile:). Only a side without its brace must
		// not run on into a longer word.
		if (text[start] != '{' && start > 0 && isWord(text[start-1])) || (text[end-1] != '}' && end < len(text) && isWord(text[end])) {
			continue
		}
		kind := strings.ToUpper(text[m[2]:m[3]])
		hash := strings.ToLower(text[m[4]:m[5]])
		placeholder := "{{" + kind + "_" + hash + "}}"
		value, ok := r.vault.Lookup(scope, placeholder)
		if !ok {
			// Written as Veil writes one, of a Kind Veil masks, yet not held:
			// one the Vault forgot, or of another caller.
			if t != nil && strings.HasPrefix(text[start:end], "{{") && strings.HasSuffix(text[start:end], "}}") && vault.IsPlaceholder(placeholder) && (detect.KnownKind(kind) || r.vault.HasKind(kind)) {
				t.miss(placeholder)
			}
			continue
		}
		t.back(placeholder)
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
	return r.BodyTally(scope, body, nil)
}

// BodyTally is Body, counting what it restores into t.
func (r *Restorer) BodyTally(scope string, body []byte, t *Tally) []byte {
	if !r.vault.HasScope(scope) {
		return nil
	}
	doc, err := jsontree.Parse(body)
	if err != nil || doc.Root.Kind != jsontree.Object {
		if !utf8.Valid(body) {
			return nil
		}
		if out, ok := r.replace(scope, string(body), false, t); ok {
			return []byte(out)
		}
		return nil
	}
	set := fields.Walk(doc)
	for _, f := range set.Fields {
		if out, ok := r.replace(scope, f.Text, false, t); ok {
			f.Doc.SetString(f.Value, out)
		}
	}
	set.Commit()
	if !doc.Changed() {
		return nil
	}
	return doc.Bytes()
}
