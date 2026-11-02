package detect

import (
	"regexp"
	"sort"
	"strings"
)

// The rule engine and the rules in rules.go, phone.go, fieldvalue.go and
// more.go are ported from yetone/magpie's internal/redact (MIT, Copyright
// (c) 2026 yetone); see THIRD_PARTY_NOTICES.md at the repository root.

const (
	alnum   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	tokenCh = alnum + "_-"
	digits  = "0123456789"
)

// rule is one pattern and the checks a match of it must pass.
type rule struct {
	id      string
	kind    Kind
	re      *regexp.Regexp
	markers []string // one of these is in any text it can match
	// fold are markers too, looked for in the text in lower case, for a
	// pattern that matches its words in any case (Passport, PASSPORT)
	fold  []string
	bound string
	ok    func(string) bool
	// at checks the value at s[a:b] by what is around it: a dotted quad
	// right after "version" is no address
	at func(s string, a, b int) bool
	// fix, where set, checks the value in place of ok and may shorten it:
	// an IBAN printed in groups of four, followed by a word in capitals
	fix func(s string, a, b int) (int, int, bool)
	// back and ahead, where ahead is set, are how far before and after
	// one of fold a match can be: the pattern is only run there, as one
	// that takes its words in any case is slow over all of a long text
	back, ahead int
	// cat is the Category that turns the rule on
	cat string
	// anyGroup takes the first group that matched, for a pattern with a
	// group in each of its alternatives
	anyGroup bool
	// groups, where set, are the kinds of a match's groups, each a value
	// of its own (the user and the host of user@host), and groupOK checks
	// each
	groups  []Kind
	groupOK []func(string) bool
}

// runRules returns the spans of the rules whose Category is on.
func runRules(s string, rules []rule, on func(cat string) bool) []span {
	var found, split []span
	lower := ""
	for i := range rules {
		r := &rules[i]
		if !on(r.cat) {
			continue
		}
		if len(r.markers) > 0 && !containsAny(s, r.markers) {
			continue
		}
		if len(r.fold) > 0 {
			if lower == "" {
				lower = lowerASCII(s)
			}
			if !containsAny(lower, r.fold) {
				continue
			}
		}
		for _, m := range r.matches(s, lower) {
			if len(r.groups) > 0 {
				took := false
				for g, kind := range r.groups {
					if a, b := m[2*g+2], m[2*g+3]; a >= 0 && r.takes(s, a, b, r.groupOK[g]) {
						found = append(found, span{a, b, kind, r.id})
						took = true
					}
				}
				if took {
					split = append(split, span{start: m[2], end: m[1]})
				}
				continue
			}
			a, b := m[0], m[1]
			for g := 1; 2*g+1 < len(m); g++ {
				if m[2*g] >= 0 {
					a, b = m[2*g], m[2*g+1]
					break
				}
				if !r.anyGroup {
					break
				}
			}
			ok := r.ok
			if r.fix != nil {
				var good bool
				if a, b, good = r.fix(s, a, b); !good {
					continue
				}
				ok = nil
			}
			if r.takes(s, a, b, ok) {
				found = append(found, span{a, b, r.kind, r.id})
			}
		}
	}
	// A match taken apart into a user and a host (rkato@box17) is no email.
	for _, sp := range split {
		kept := found[:0]
		for _, f := range found {
			if !(f.kind == KindEmail && f.start == sp.start && f.end <= sp.end) {
				kept = append(kept, f)
			}
		}
		found = kept
	}
	return found
}

// matches are r's matches in s, lower being lowerASCII(s): in all of s,
// or, for a rule with ahead set, only around its fold markers.
func (r *rule) matches(s, lower string) [][]int {
	if r.ahead == 0 {
		return r.re.FindAllStringSubmatchIndex(s, -1)
	}
	var wins [][2]int
	for _, f := range r.fold {
		for i := 0; ; {
			j := strings.Index(lower[i:], f)
			if j < 0 {
				break
			}
			at := i + j
			i = at + len(f)
			// from the line's start, or from where a word starts no further
			// back than back
			start := max(0, at-r.back)
			if nl := strings.LastIndexByte(s[start:at], '\n'); nl >= 0 {
				start += nl + 1
			} else if start > 0 {
				for start < at && (strings.IndexByte(alnum+"_.-", s[start-1]) >= 0 || s[start]&0xc0 == 0x80) {
					start++
				}
				if start == at && strings.IndexByte(alnum+"_", s[at-1]) >= 0 {
					continue // inside a longer word
				}
			}
			wins = append(wins, [2]int{start, min(len(s), i+r.ahead)})
		}
	}
	sort.Slice(wins, func(i, j int) bool { return wins[i][0] < wins[j][0] })
	var out [][]int
	for k := 0; k < len(wins); k++ {
		w := wins[k]
		for k+1 < len(wins) && wins[k+1][0] <= w[1] {
			k++
			w[1] = max(w[1], wins[k][1])
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(s[w[0]:w[1]], -1) {
			for x := range m {
				if m[x] >= 0 {
					m[x] += w[0]
				}
			}
			out = append(out, m)
		}
	}
	return out
}

// takes says s[a:b] is a value r finds: nothing it may not touch beside it,
// and its checks pass.
func (r *rule) takes(s string, a, b int, ok func(string) bool) bool {
	if b <= a {
		return false
	}
	if r.bound != "" && (a > 0 && strings.IndexByte(r.bound, s[a-1]) >= 0 || b < len(s) && strings.IndexByte(r.bound, s[b]) >= 0) {
		return false
	}
	if ok != nil && !ok(s[a:b]) {
		return false
	}
	return r.at == nil || r.at(s, a, b)
}

// lowerASCII is s with its ASCII letters in lower case, as long as s, so a
// place in one is the same place in the other.
func lowerASCII(s string) string {
	i := 0
	for i < len(s) && !('A' <= s[i] && s[i] <= 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		b[i] = lowerByte(b[i])
	}
	return string(b)
}

func lowerByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func wordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
