package mask

import (
	"strings"
	"unicode/utf8"

	"github.com/GarlandQian/cpa-plugin-veil/internal/detect"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// Value is one value a request had, as a Masking record tells it: by what it
// goes upstream as and a hint, never by the value itself.
type Value struct {
	// Placeholder is its Placeholder or Stand-in; for a value sent as written
	// or held back, the one it would have gone as.
	Placeholder string
	Kind        string
	// Rule names what found it: a detection rule's ID, RuleSecretField for a
	// field named for a secret, RuleKnown for a Known value.
	Rule string
	// Head is a key's well-known prefix or its first character, and Len its
	// length in characters.
	Head string
	Len  int
	// N is how many places of the request had it, and Paths the fields.
	N      int
	Paths  []string
	Action Action
	// New says no earlier request of the Caller scope had it.
	New bool
	// Snip is the text around its first place as the upstream got it, with
	// every value the request had in Placeholders, sent as written or not.
	Snip string
}

// Rule names for the values no detection rule names.
const (
	RuleSecretField = "secret-field"
	RuleKnown       = "known"
)

// snipRunes is how much text a Snip keeps on either side of its value.
const snipRunes = 40

// keyPrefixes are the starts that tell a key's vendor, longest first; a Head
// is never more than half of the value.
var keyPrefixes = []string{
	"sk-proj-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_",
	"sk-ant-", "github_", "Bearer ", "shpat_", "shpss_", "glpat-", "whsec_",
	"sk-or-", "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xapp-", "pypi-", "ya29.",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "AKIA", "ASIA", "AIza", "npm_",
	"sk-", "hf_", "SG.", "eyJ",
}

// hint is what a record may show of a value of kind.
func hint(kind, value string) string {
	if kind == string(detect.KindPrivateKey) {
		return ""
	}
	if kind == string(detect.KindSecret) {
		for _, p := range keyPrefixes {
			if strings.HasPrefix(value, p) && 2*len(p) < len(value) {
				return p
			}
		}
	}
	if utf8.RuneCountInString(value) < 3 {
		return ""
	}
	_, size := utf8.DecodeRuneInString(value)
	return value[:size]
}

// valueSet gathers a request's Values, one per Placeholder, in the order the
// request first had them.
type valueSet struct {
	at   map[string]int
	list []Value
}

func newValueSet() *valueSet {
	return &valueSet{at: map[string]int{}}
}

// addField adds the values of one field: text masked at spans, each going as
// reps[i]. fresh are the Placeholders minted for the first time by this
// request. With snips, a Value first met here takes the text around it.
func (vs *valueSet) addField(text, path string, spans []span, reps []string, action func(string) Action, fresh map[string]bool, snips bool) {
	var wanted []int // the spans a Snip is cut around
	for i, s := range spans {
		p := reps[i]
		if j, ok := vs.at[p]; ok {
			v := &vs.list[j]
			v.N++
			if v.Paths[len(v.Paths)-1] != path {
				v.Paths = appendNew(v.Paths, path)
			}
			continue
		}
		raw := text[s.start:s.end]
		vs.at[p] = len(vs.list)
		vs.list = append(vs.list, Value{
			Placeholder: p,
			Kind:        s.kind,
			Rule:        s.rule,
			Head:        hint(s.kind, raw),
			Len:         utf8.RuneCountInString(raw),
			N:           1,
			Paths:       []string{path},
			Action:      action(s.kind),
			New:         fresh[p],
		})
		if snips {
			wanted = append(wanted, i)
		}
	}
	if len(wanted) == 0 {
		return
	}
	// The text with every span in its Placeholder, so a Snip never holds a
	// value, not even one the warn Action sent as written.
	var b strings.Builder
	at := make([][2]int, len(spans))
	prev := 0
	for i, s := range spans {
		b.WriteString(text[prev:s.start])
		at[i][0] = b.Len()
		b.WriteString(reps[i])
		at[i][1] = b.Len()
		prev = s.end
	}
	b.WriteString(text[prev:])
	safe := b.String()
	for _, i := range wanted {
		vs.list[vs.at[reps[i]]].Snip = snip(safe, at[i][0], at[i][1])
	}
}

func appendNew(paths []string, path string) []string {
	for _, p := range paths {
		if p == path {
			return paths
		}
	}
	return append(paths, path)
}

// snip is text[a:b] with up to snipRunes characters on either side.
func snip(text string, a, b int) string {
	start := a
	for n := 0; n < snipRunes && start > 0; n++ {
		_, size := utf8.DecodeLastRuneInString(text[:start])
		start -= size
	}
	end := b
	for n := 0; n < snipRunes && end < len(text); n++ {
		_, size := utf8.DecodeRuneInString(text[end:])
		end += size
	}
	return text[start:end]
}

// Preview returns text as the upstream would get it under m's policy, and
// the values found, without touching the Vault: nothing is recorded, Known
// values and Sent forms are neither read nor changed, and each Placeholder
// is the one the Default scope would have, for show.
func (m *Masker) Preview(text string) (string, []Value) {
	var hits []span
	for _, h := range m.detector.Detect(text) {
		hits = append(hits, span{h.Start, h.End, string(h.Kind), h.Rule})
	}
	hits = outsidePlaceholders(text, hits)
	if len(hits) == 0 {
		return text, nil
	}
	reps := make([]string, len(hits))
	var b strings.Builder
	prev := 0
	for i, s := range hits {
		reps[i] = m.vault.Peek(vault.DefaultScope, s.kind, text[s.start:s.end])
		if m.action(s.kind) == Warn {
			continue
		}
		b.WriteString(text[prev:s.start])
		b.WriteString(reps[i])
		prev = s.end
	}
	b.WriteString(text[prev:])
	values := newValueSet()
	values.addField(text, "", hits, reps, m.action, nil, false)
	return b.String(), values.list
}
