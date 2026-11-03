// Package detect finds sensitive spans in text: credentials and secrets,
// structured personal data, and what the user lists. Pure regular
// expressions, no model, linear in the text. A Detector is read-only once
// built and safe for concurrent use.
//
// The gitleaks layer derives from github.com/packyme/privacy-filter (MIT,
// Copyright (c) 2026 PackyMe) and the context, personal and optional rules
// from yetone/magpie (MIT, Copyright (c) 2026 yetone); see
// THIRD_PARTY_NOTICES.md at the repository root.
package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Kind is what sort of sensitive value a Hit is.
type Kind string

const (
	KindSecret     Kind = "SECRET"
	KindPassword   Kind = "PASSWORD"
	KindPrivateKey Kind = "PRIVATE_KEY"
	KindEmail      Kind = "EMAIL"
	KindPhone      Kind = "PHONE"
	KindIDCard     Kind = "ID_CARD"
	KindBankCard   Kind = "BANK_CARD"
	KindSSN        Kind = "SSN"
	KindPassport   Kind = "PASSPORT"
	KindIBAN       Kind = "IBAN"
	KindBirthday   Kind = "BIRTHDAY"
	KindMAC        Kind = "MAC"
	KindSerial     Kind = "SERIAL"
	KindUsername   Kind = "USERNAME"
	KindHostname   Kind = "HOSTNAME"
	KindIP         Kind = "IP"
	KindBucket     Kind = "BUCKET"
	KindTerm       Kind = "TERM"
)

// customKind is what a user rule may call its Kind.
var customKind = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,23}$`)

const (
	catSecrets  = "secrets"
	catPersonal = "personal"
)

// Category is a group of detections switched on or off as a whole.
type Category struct {
	ID    string
	Kinds []Kind
	On    bool
}

// Categories are every Category and whether it is on by default.
var Categories = []Category{
	{ID: catSecrets, Kinds: []Kind{KindSecret, KindPassword, KindPrivateKey}, On: true},
	{ID: catPersonal, Kinds: []Kind{KindEmail, KindPhone, KindIDCard, KindBankCard}, On: true},
	{ID: "ssn", Kinds: []Kind{KindSSN}, On: true},
	{ID: "passport", Kinds: []Kind{KindPassport}, On: true},
	{ID: "iban", Kinds: []Kind{KindIBAN}, On: true},
	{ID: "birthday", Kinds: []Kind{KindBirthday}, On: true},
	{ID: "mac", Kinds: []Kind{KindMAC}, On: true},
	{ID: "serial", Kinds: []Kind{KindSerial}, On: true},
	{ID: "home", Kinds: []Kind{KindUsername}},
	{ID: "userhost", Kinds: []Kind{KindUsername, KindHostname}},
	{ID: "ip", Kinds: []Kind{KindIP}},
	{ID: "bucket", Kinds: []Kind{KindBucket}},
}

// Term is a word the user lists to be masked wherever it appears.
type Term struct {
	Text      string
	AnyCase   bool
	WholeWord bool
}

// Options are the user's settings for a Detector.
type Options struct {
	// Categories turns Categories on or off over their defaults.
	Categories map[string]bool
	Terms      []Term
	// Allow are values never masked, compared whole and in any case.
	Allow []string
	// DisabledRules are rule IDs to turn off, built-in or gitleaks.
	DisabledRules []string
	// ExtraRules are gitleaks rules in TOML added to the built-in ones. A
	// rule may set kind to name its Kind; it is SECRET otherwise.
	ExtraRules []byte
}

// Hit is one sensitive span of the text. Start and End are UTF-8 byte
// offsets; Rule names the detection that found it.
type Hit struct {
	Start int
	End   int
	Kind  Kind
	Rule  string
}

// span is what each detection layer produces before overlaps are resolved.
type span struct {
	start, end int
	kind       Kind
	rule       string
}

// Detector holds the compiled rules and the user's settings.
type Detector struct {
	secrets *secretDetector
	rules   []rule
	cats    map[string]bool
	terms   []termRule
	allow   map[string]bool
	// user are the rules the user wrote, which the guards leave alone
	user  map[string]bool
	cache *hitCache
}

// termRule finds one Term.
type termRule struct {
	re    *regexp.Regexp
	whole bool
}

// New builds a Detector from gitleaks rules in TOML and the user's
// options. Empty rules use a small built-in fallback set; so does a file in
// which no rule compiles.
func New(rules []byte, opts Options) (*Detector, error) {
	d := &Detector{cats: map[string]bool{}, allow: map[string]bool{}, user: map[string]bool{"term": true}, cache: newHitCache()}
	for _, c := range Categories {
		d.cats[c.ID] = c.On
	}
	for id, on := range opts.Categories {
		if _, ok := d.cats[id]; !ok {
			return nil, fmt.Errorf("unknown category %q", id)
		}
		d.cats[id] = on
	}

	disabled := map[string]bool{}
	for _, id := range opts.DisabledRules {
		disabled[strings.TrimSpace(id)] = true
	}
	sd, err := newSecretDetector(rules, opts.ExtraRules, disabled)
	if err != nil {
		return nil, err
	}
	d.secrets = sd
	for id := range sd.user {
		d.user[id] = true
	}
	known := map[string]bool{}
	for _, r := range sd.all {
		known[r] = true
	}
	for _, r := range append(append([]rule(nil), contextRules...), moreRules...) {
		known[r.id] = true
		if !disabled[r.id] {
			d.rules = append(d.rules, r)
		}
	}
	for id := range disabled {
		if !known[id] {
			return nil, fmt.Errorf("disabled_rules: no rule %q", id)
		}
	}

	for _, t := range opts.Terms {
		if strings.TrimSpace(t.Text) == "" {
			return nil, fmt.Errorf("terms: empty term")
		}
		pattern := regexp.QuoteMeta(t.Text)
		if t.AnyCase {
			pattern = "(?i)" + pattern
		}
		d.terms = append(d.terms, termRule{re: regexp.MustCompile(pattern), whole: t.WholeWord})
	}
	for _, v := range opts.Allow {
		if v = strings.TrimSpace(v); v != "" {
			d.allow[strings.ToLower(v)] = true
		}
	}
	return d, nil
}

// Stats returns how many gitleaks rules loaded and how many were skipped
// because Go's regexp engine cannot compile them.
func (d *Detector) Stats() (rules, skipped int) {
	return len(d.secrets.rules), d.secrets.skipped
}

// Detect returns the sensitive spans of text, ordered by start and never
// overlapping. The result belongs to the caller.
func (d *Detector) Detect(text string) []Hit {
	key, cacheable := cacheKey(text)
	if cacheable {
		if hits, ok := d.cache.get(key); ok {
			return hits
		}
	}
	hits := d.detect(text)
	if cacheable {
		d.cache.put(key, hits)
	}
	return hits
}

// detect runs every layer on text, bypassing the cache.
func (d *Detector) detect(text string) []Hit {
	on := func(cat string) bool { return d.cats[cat] }
	spans := runRules(text, d.rules, on)
	if on(catSecrets) {
		spans = append(spans, d.secrets.detect(text)...)
	}
	spans = d.guard(text, spans)
	spans = append(spans, d.findTerms(text)...)
	if len(d.allow) > 0 {
		kept := spans[:0]
		for _, s := range spans {
			if !d.allow[strings.ToLower(text[s.start:s.end])] {
				kept = append(kept, s)
			}
		}
		spans = kept
	}
	merged := mergeSpans(spans)
	hits := make([]Hit, len(merged))
	for i, s := range merged {
		hits[i] = Hit{Start: s.start, End: s.end, Kind: s.kind, Rule: s.rule}
	}
	return hits
}

// findTerms finds the user's terms; a whole-word term is not a piece of a
// longer word.
func (d *Detector) findTerms(text string) []span {
	var out []span
	for _, t := range d.terms {
		for _, m := range t.re.FindAllStringIndex(text, -1) {
			if t.whole && (m[0] > 0 && wordByte(text[m[0]-1]) || m[1] < len(text) && wordByte(text[m[1]])) {
				continue
			}
			out = append(out, span{m[0], m[1], KindTerm, "term"})
		}
	}
	return out
}

// mergeSpans 丢弃无效与重叠区间：按起点升序、同起点取更长者，
// 贪心保留互不重叠的区间。原地压缩调用方的内部切片，避免复制候选区间。
func mergeSpans(spans []span) []span {
	valid := spans[:0]
	for _, s := range spans {
		if s.start >= 0 && s.start < s.end {
			valid = append(valid, s)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].start != valid[j].start {
			return valid[i].start < valid[j].start
		}
		return valid[i].end > valid[j].end
	})
	merged := valid[:0]
	lastEnd := -1
	for _, s := range valid {
		if s.start >= lastEnd {
			merged = append(merged, s)
			lastEnd = s.end
		}
	}
	return merged
}

// KnownKind reports whether kind is one of Veil's own Kinds.
func KnownKind(kind string) bool {
	if Kind(kind) == KindTerm {
		return true
	}
	for _, c := range Categories {
		for _, k := range c.Kinds {
			if string(k) == kind {
				return true
			}
		}
	}
	return false
}
