// Package mask replaces the sensitive values of a request with their
// Placeholders.
package mask

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/fields"
	"github.com/GarlandQian/cpa-plugin-veil/internal/jsontree"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// Action is what Veil does with a value of a Kind.
type Action string

const (
	// Mask replaces the value with its Placeholder; the default.
	Mask Action = "mask"
	// Block stops the whole request.
	Block Action = "block"
	// Warn lets the value through and reports it.
	Warn Action = "warn"
)

// ErrMalformed is returned for a body that starts like JSON but does not
// parse, so Veil cannot tell what in it is sensitive.
var ErrMalformed = errors.New("request body is not valid JSON")

// Masker masks requests with one detector, one vault and one set of Actions.
type Masker struct {
	detector *detect.Detector
	vault    *vault.Vault
	sent     *sentForms
	actions  map[string]Action
}

// New returns a Masker that masks every Kind.
func New(d *detect.Detector, v *vault.Vault) *Masker {
	return &Masker{detector: d, vault: v, sent: newSentForms()}
}

// WithPolicy returns a Masker that detects with d, acts on Kinds as actions
// say (Mask where they say nothing) and shares m's vault and Sent forms, for
// a config reload.
func (m *Masker) WithPolicy(d *detect.Detector, actions map[string]Action) *Masker {
	return &Masker{detector: d, vault: m.vault, sent: m.sent, actions: actions}
}

func (m *Masker) action(kind string) Action {
	if a, ok := m.actions[kind]; ok {
		return a
	}
	return Mask
}

// Report says what Veil found in a request, per Action: the JSON paths of the
// fields, in document order, and how many values of each Kind. It never holds
// a value.
type Report struct {
	Paths  []string
	Counts map[string]int
	// Warned are values let through by the warn Action.
	WarnedPaths  []string
	Warned       map[string]int
	BlockedPaths []string
	Blocked      map[string]int
}

// Total returns how many values were masked.
func (r Report) Total() int {
	return total(r.Counts)
}

func total(counts map[string]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

// tally adds one value of kind found at path to a count and a path list.
func tally(counts map[string]int, paths *[]string, kind, path string) {
	counts[kind]++
	if n := len(*paths); n == 0 || (*paths)[n-1] != path {
		for _, p := range *paths {
			if p == path {
				return
			}
		}
		*paths = append(*paths, path)
	}
}

// minFieldLen is the shortest string worth looking at: nothing Veil detects
// is shorter.
const minFieldLen = 4

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
	if err != nil {
		if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
			return nil, Report{}, ErrMalformed
		}
		return nil, Report{}, nil
	}
	if doc.Root.Kind != jsontree.Object {
		return nil, Report{}, nil
	}
	w := fields.Walk(doc)
	if len(w.Fields) == 0 {
		return nil, Report{}, nil
	}

	type pending struct {
		key  [sha256.Size]byte
		hits []span
	}
	spans := make([][]span, len(w.Fields))
	fresh := map[int]*pending{}
	for i, f := range w.Fields {
		if len(f.Text) < minFieldLen {
			continue
		}
		key := sentKey(scope, f.Text)
		if frozen, ok := m.sent.get(key); ok {
			spans[i] = frozen
			continue
		}
		var hits []span
		if detect.SecretField(fieldKey(f.Path), f.Text) {
			// A field named for a secret holds one whatever it looks like:
			// {"api_key": "…"} with a value no rule knows.
			hits = []span{{0, len(f.Text), string(detect.KindSecret)}}
		} else {
			for _, h := range m.detector.Detect(f.Text) {
				hits = append(hits, span{h.Start, h.End, string(h.Kind)})
			}
		}
		hits = outsidePlaceholders(f.Text, hits)
		hits = m.notStandIns(scope, f.Text, hits)
		// Minting makes the value Known, so it is masked across the request.
		for _, h := range hits {
			if m.action(h.kind) == Mask {
				m.vault.Placeholder(scope, h.kind, f.Text[h.start:h.end])
			}
		}
		fresh[i] = &pending{key: key, hits: hits}
	}
	for i, p := range fresh {
		f := w.Fields[i]
		var known []span
		for _, k := range m.vault.KnownMatches(scope, f.Text) {
			known = append(known, span{k.Start, k.End, k.Kind})
		}
		spans[i] = merge(p.hits, outsidePlaceholders(f.Text, known))
	}

	report := Report{Counts: map[string]int{}, Warned: map[string]int{}, Blocked: map[string]int{}}
	for i, f := range w.Fields {
		for _, s := range spans[i] {
			if m.action(s.kind) == Block {
				tally(report.Blocked, &report.BlockedPaths, s.kind, f.Path)
			}
		}
	}
	if len(report.Blocked) > 0 {
		// The request never goes out, so nothing of it was sent.
		return nil, report, nil
	}
	for i, p := range fresh {
		m.sent.put(p.key, spans[i])
	}

	for i, f := range w.Fields {
		var b strings.Builder
		prev := 0
		for _, s := range spans[i] {
			if m.action(s.kind) == Warn {
				tally(report.Warned, &report.WarnedPaths, s.kind, f.Path)
				continue
			}
			b.WriteString(f.Text[prev:s.start])
			b.WriteString(m.vault.Placeholder(scope, s.kind, f.Text[s.start:s.end]))
			prev = s.end
			tally(report.Counts, &report.Paths, s.kind, f.Path)
		}
		if prev == 0 {
			continue
		}
		b.WriteString(f.Text[prev:])
		f.Doc.SetString(f.Value, b.String())
	}
	w.Commit()
	if !doc.Changed() {
		return nil, report, nil
	}
	return doc.Bytes(), report, nil
}

// notStandIns drops the hits that are a Stand-in already: a home folder
// masked once reads /Users/qmzvkrta, which the home rule finds again.
func (m *Masker) notStandIns(scope, text string, hits []span) []span {
	if !m.vault.HasStandIns(scope) {
		return hits
	}
	out := hits[:0]
	for _, h := range hits {
		if !m.vault.IsStandIn(scope, text[h.start:h.end]) {
			out = append(out, h)
		}
	}
	return out
}

// fieldKey is the name of the member a field is the value of, or "" for
// an array's element.
func fieldKey(path string) string {
	key := path[strings.LastIndexByte(path, '.')+1:]
	if strings.HasSuffix(key, "]") {
		return ""
	}
	return key
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
