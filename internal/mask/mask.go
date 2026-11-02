// Package mask replaces the sensitive values of a request with their
// Placeholders.
package mask

import (
	"crypto/sha256"
	"sort"
	"strings"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/jsontree"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// Masker masks requests with one detector and one vault.
type Masker struct {
	detector *detect.Detector
	vault    *vault.Vault
	sent     *sentForms
}

// New returns a Masker.
func New(d *detect.Detector, v *vault.Vault) *Masker {
	return &Masker{detector: d, vault: v, sent: newSentForms()}
}

// WithDetector returns a Masker that detects with d and shares m's vault and
// Sent forms, for a config reload that changes the rules.
func (m *Masker) WithDetector(d *detect.Detector) *Masker {
	return &Masker{detector: d, vault: m.vault, sent: m.sent}
}

// Report says what a request had masked: the JSON paths of the fields, in
// document order, and how many values of each Kind. It never holds a value.
type Report struct {
	Paths  []string
	Counts map[string]int
}

// Total returns how many values were masked.
func (r Report) Total() int {
	n := 0
	for _, c := range r.Counts {
		n += c
	}
	return n
}

// span is one value of a field to mask.
type span struct {
	start, end int
	kind       string
}

// Mask returns body with its sensitive values replaced by their Placeholders
// in scope, or nil when nothing changed. A body that is not a JSON object
// passes through.
//
// A field already sent upstream in scope keeps its Sent form. Any other
// field is masked where the rules find values and wherever a Known value of
// scope reappears, which includes every value found anywhere in this
// request: a secret found by its context in one place is masked where it
// appears without context too.
func (m *Masker) Mask(scope string, body []byte) ([]byte, Report, error) {
	doc, err := jsontree.Parse(body)
	if err != nil || doc.Root.Kind != jsontree.Object {
		return nil, Report{}, nil
	}
	w := &walker{}
	w.root(doc)
	if len(w.fields) == 0 {
		return nil, Report{}, nil
	}

	type pending struct {
		key  [sha256.Size]byte
		hits []span
	}
	spans := make([][]span, len(w.fields))
	fresh := map[int]*pending{}
	for i, f := range w.fields {
		key := sentKey(scope, f.text)
		if frozen, ok := m.sent.get(key); ok {
			spans[i] = frozen
			continue
		}
		var hits []span
		for _, h := range m.detector.Detect(f.text) {
			hits = append(hits, span{h.Start, h.End, string(h.Kind)})
		}
		hits = outsidePlaceholders(f.text, hits)
		// Minting makes the value Known, so it is masked across the request.
		for _, h := range hits {
			m.vault.Placeholder(scope, h.kind, f.text[h.start:h.end])
		}
		fresh[i] = &pending{key: key, hits: hits}
	}
	for i, p := range fresh {
		f := w.fields[i]
		var known []span
		for _, k := range m.vault.KnownMatches(scope, f.text) {
			known = append(known, span{k.Start, k.End, k.Kind})
		}
		spans[i] = merge(p.hits, outsidePlaceholders(f.text, known))
		m.sent.put(p.key, spans[i])
	}

	report := Report{Counts: map[string]int{}}
	seen := map[string]bool{}
	for i, f := range w.fields {
		if len(spans[i]) == 0 {
			continue
		}
		var b strings.Builder
		prev := 0
		for _, s := range spans[i] {
			b.WriteString(f.text[prev:s.start])
			b.WriteString(m.vault.Placeholder(scope, s.kind, f.text[s.start:s.end]))
			prev = s.end
			report.Counts[s.kind]++
		}
		b.WriteString(f.text[prev:])
		f.doc.SetString(f.value, b.String())
		if !seen[f.path] {
			seen[f.path] = true
			report.Paths = append(report.Paths, f.path)
		}
	}
	// Inner documents first: an argument string can sit inside another.
	for i := len(w.nested) - 1; i >= 0; i-- {
		n := w.nested[i]
		if n.inner.Changed() {
			n.outer.SetString(n.value, string(n.inner.Bytes()))
		}
	}
	if !doc.Changed() {
		return nil, Report{}, nil
	}
	return doc.Bytes(), report, nil
}

func sentKey(scope, text string) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(text))
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

// outsidePlaceholders drops spans that touch a Placeholder already in text.
func outsidePlaceholders(text string, spans []span) []span {
	placeholders := vault.PlaceholderSpans(text)
	if len(placeholders) == 0 || len(spans) == 0 {
		return spans
	}
	out := spans[:0]
	for _, s := range spans {
		inside := false
		for _, p := range placeholders {
			if s.start < p[1] && s.end > p[0] {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, s)
		}
	}
	return out
}

// merge adds the known spans that do not overlap a rule hit, ordered by
// start.
func merge(hits, known []span) []span {
	out := append([]span(nil), hits...)
	for _, k := range known {
		overlaps := false
		for _, h := range hits {
			if k.start < h.end && k.end > h.start {
				overlaps = true
				break
			}
		}
		if !overlaps {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// sentForms remembers, per Caller scope and text, the spans a text was
// masked at the first time it went upstream, in two bounded generations.
type sentForms struct {
	mu   sync.Mutex
	cur  map[[sha256.Size]byte][]span
	prev map[[sha256.Size]byte][]span
}

// sentGenSize is how many texts one generation holds.
const sentGenSize = 1 << 17

func newSentForms() *sentForms {
	return &sentForms{cur: make(map[[sha256.Size]byte][]span)}
}

func (s *sentForms) get(key [sha256.Size]byte) ([]span, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if spans, ok := s.cur[key]; ok {
		return spans, true
	}
	spans, ok := s.prev[key]
	if ok {
		s.store(key, spans)
	}
	return spans, ok
}

func (s *sentForms) put(key [sha256.Size]byte, spans []span) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store(key, spans)
}

func (s *sentForms) store(key [sha256.Size]byte, spans []span) {
	if len(s.cur) >= sentGenSize {
		s.prev = s.cur
		s.cur = make(map[[sha256.Size]byte][]span, sentGenSize)
	}
	s.cur[key] = spans
}
