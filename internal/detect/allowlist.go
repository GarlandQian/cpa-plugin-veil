package detect

import (
	"regexp"
	"strings"
)

// tomlAllowlist is a gitleaks allowlist as its TOML has it, a rule's or the
// file's own.
type tomlAllowlist struct {
	Condition   string   `toml:"condition"`
	RegexTarget string   `toml:"regexTarget"`
	Regexes     []string `toml:"regexes"`
	StopWords   []string `toml:"stopwords"`
	Paths       []string `toml:"paths"`
	Commits     []string `toml:"commits"`
}

// allowlist lets a gitleaks finding through as gitleaks does: when one of its
// regexes matches the secret (or the whole match, or its line) or the secret
// holds one of its stop words; with the AND condition, when all of those it
// has do. Paths and commits never match, a request having neither.
type allowlist struct {
	and     bool
	target  string // "secret", "match" or "line"
	regexes []*regexp.Regexp
	stops   []string // in lower case
	never   bool     // AND over paths or commits
}

func newAllowlist(t tomlAllowlist) allowlist {
	a := allowlist{and: strings.EqualFold(t.Condition, "AND"), target: strings.ToLower(t.RegexTarget)}
	for _, r := range t.Regexes {
		// A pattern RE2 cannot take is left out, as rules are.
		if re, err := regexp.Compile(r); err == nil {
			a.regexes = append(a.regexes, re)
		}
	}
	for _, w := range t.StopWords {
		if w != "" {
			a.stops = append(a.stops, strings.ToLower(w))
		}
	}
	a.never = a.and && (len(t.Paths) > 0 || len(t.Commits) > 0)
	return a
}

// empty says a can let nothing through.
func (a allowlist) empty() bool {
	return a.never || len(a.regexes) == 0 && len(a.stops) == 0
}

// allows says the finding text[s:e] of the match text[ms:me] is let through.
func (a allowlist) allows(text string, s, e, ms, me int) bool {
	if a.empty() {
		return false
	}
	var checks []bool
	if len(a.regexes) > 0 {
		target := text[s:e]
		switch a.target {
		case "match":
			target = text[ms:me]
		case "line":
			lo := strings.LastIndexByte(text[:ms], '\n') + 1
			hi := strings.IndexByte(text[me:], '\n')
			if hi < 0 {
				hi = len(text)
			} else {
				hi += me
			}
			target = text[lo:hi]
		}
		matched := false
		for _, re := range a.regexes {
			if re.MatchString(target) {
				matched = true
				break
			}
		}
		checks = append(checks, matched)
	}
	if len(a.stops) > 0 {
		secret, stopped := strings.ToLower(text[s:e]), false
		for _, w := range a.stops {
			if strings.Contains(secret, w) {
				stopped = true
				break
			}
		}
		checks = append(checks, stopped)
	}
	for _, ok := range checks {
		if ok && !a.and {
			return true
		}
		if !ok && a.and {
			return false
		}
	}
	return a.and
}

// allowlists gathers a TOML table's allowlists: the single [allowlist] of an
// older file and the [[allowlists]] of a newer one.
func allowlists(one *tomlAllowlist, many []tomlAllowlist) []allowlist {
	var out []allowlist
	if one != nil {
		many = append([]tomlAllowlist{*one}, many...)
	}
	for _, t := range many {
		if a := newAllowlist(t); !a.empty() {
			out = append(out, a)
		}
	}
	return out
}
