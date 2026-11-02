// Package detect finds sensitive spans in text: structured personal data,
// credentials and secrets. Pure regular expressions, no model, linear in the
// text. A Detector is read-only once built and safe for concurrent use.
//
// It derives from github.com/packyme/privacy-filter (MIT, Copyright (c) 2026
// PackyMe); see THIRD_PARTY_NOTICES.md at the repository root.
package detect

import "sort"

// Kind is what sort of sensitive value a Hit is.
type Kind string

const (
	KindEmail    Kind = "EMAIL"
	KindPhone    Kind = "PHONE"
	KindIDCard   Kind = "ID_CARD"
	KindBankCard Kind = "BANK_CARD"
	KindIP       Kind = "IP"
	KindSecret   Kind = "SECRET"
)

// Hit is one sensitive span of the text. Start and End are UTF-8 byte offsets;
// Rule names the detection that found it.
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

// Detector holds the compiled rules.
type Detector struct {
	secrets *secretDetector
	cache   *hitCache
}

// New builds a Detector from gitleaks rules in TOML. Empty rules use a small
// built-in fallback set; so does a file in which no rule compiles.
func New(rules []byte) (*Detector, error) {
	sd, err := newSecretDetector(rules)
	if err != nil {
		return nil, err
	}
	return &Detector{secrets: sd, cache: newHitCache()}, nil
}

// Stats returns how many rules loaded and how many were skipped because Go's
// regexp engine cannot compile them.
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
	var spans []span
	spans = append(spans, detectPII(text)...)        // 结构化 PII
	spans = append(spans, d.secrets.detect(text)...) // 密钥 / 凭证
	merged := mergeSpans(spans)
	hits := make([]Hit, len(merged))
	for i, s := range merged {
		hits[i] = Hit{Start: s.start, End: s.end, Kind: s.kind, Rule: s.rule}
	}
	return hits
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
