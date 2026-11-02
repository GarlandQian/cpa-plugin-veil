package detect

import (
	"regexp"
	"strings"
)

// An id a backend made (a UUID, 32 hex digits or more, a short digest)
// goes as written: the model writes it back into a tool call, and a backend
// looks it up by every character. A piece of one is never a value of its
// own (a phone's form at the end of …-a13800138000, a card's across a
// UUID's groups), and a whole one is only a credential's. A number with a
// point is a measure, and a bare JSON number a count or a time, never a
// phone or a card. What the user chose (terms, their rules) stays theirs.

var uuidRe = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// guard drops the spans no rule should have found.
func (d *Detector) guard(s string, spans []span) []span {
	kept := spans[:0]
	for _, f := range spans {
		if d.user[f.rule] {
			kept = append(kept, f)
			continue
		}
		if l, r, ok := idAround(s, f.start, f.end); ok {
			if f.start > l || f.end < r {
				continue // a piece of an id
			}
			if f.kind != KindSecret && f.kind != KindPassword && f.kind != KindPrivateKey {
				continue
			}
		}
		if personal(f.kind) && (inDecimal(s, f.start, f.end) || jsonNumber(s, f.start, f.end)) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// personal says kind is personal data's rather than a secret's.
func personal(kind Kind) bool {
	switch kind {
	case KindSecret, KindPassword, KindPrivateKey, KindTerm:
		return false
	}
	return true
}

func hexOrHyphen(c byte) bool {
	return c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// idAround is the id that s[a:b] is in, or is: the run of hex digits and
// hyphens around it, when that run is a UUID, 32 hex digits or more, or a
// short digest standing as a word.
func idAround(s string, a, b int) (l, r int, ok bool) {
	l, r = a, b
	for l > 0 && hexOrHyphen(s[l-1]) {
		l--
	}
	for r < len(s) && hexOrHyphen(s[r]) {
		r++
	}
	for l < r && s[l] == '-' {
		l++
	}
	for r > l && s[r-1] == '-' {
		r--
	}
	if a < l || b > r || strings.IndexFunc(s[l:r], func(c rune) bool { return c > 0x7f || !hexOrHyphen(byte(c)) }) >= 0 || !idShaped(s[l:r]) {
		return 0, 0, false
	}
	if digestShaped(s[l:r]) && (l > 0 && wordByte(s[l-1]) || r < len(s) && wordByte(s[r])) {
		return 0, 0, false
	}
	return l, r, true
}

// idShaped says v, hex digits and hyphens, is a UUID, 32 hex digits or more
// without a hyphen, or a shorter digest.
func idShaped(v string) bool {
	return uuidRe.MatchString(v) || len(v) >= 32 && !strings.Contains(v, "-") || digestShaped(v)
}

// digestShaped says v is 16 to 31 hex digits in one case, letters and
// digits both, as a short commit or a 64-bit hash is written.
func digestShaped(v string) bool {
	if len(v) < 16 || len(v) >= 32 {
		return false
	}
	var lower, upper, nums int
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			nums++
		case c >= 'a' && c <= 'f':
			lower++
		case c >= 'A' && c <= 'F':
			upper++
		default:
			return false
		}
	}
	letters := lower + upper
	return (lower == 0 || upper == 0) && letters >= max(3, len(v)/8) && nums >= max(3, len(v)/8)
}

// inDecimal says s[a:b] is digits right after or right before a decimal
// point: 5.13800138000, 13800138000.5.
func inDecimal(s string, a, b int) bool {
	isDigit := func(i int) bool { return i >= 0 && i < len(s) && s[i] >= '0' && s[i] <= '9' }
	return isDigit(a) && a >= 2 && s[a-1] == '.' && isDigit(a-2) ||
		isDigit(b-1) && b+1 < len(s) && s[b] == '.' && isDigit(b+1)
}

// jsonNumber says s[a:b] is all of a bare JSON number, an object's value
// or an array's element: "timestamp": 17929036837.
func jsonNumber(s string, a, b int) bool {
	if a >= b || strings.Trim(s[a:b], digits) != "" {
		return false
	}
	space := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	k := b
	for k < len(s) && space(s[k]) {
		k++
	}
	if k < len(s) && strings.IndexByte(",}]", s[k]) < 0 {
		return false
	}
	i := a - 1
	for i >= 0 && space(s[i]) {
		i--
	}
	return i >= 0 && strings.IndexByte(":[,", s[i]) >= 0 && (k == len(s) || strings.IndexByte(",}]", s[k]) >= 0)
}
