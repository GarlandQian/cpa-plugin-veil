// Package vault mints Placeholders and maps them back to the values they
// stand for. Placeholders are deterministic: the same value of the same Kind
// in the same Caller scope always gets the same Placeholder under one key, so
// re-sent history masks to the same text every turn and across restarts.
package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// DefaultLimit is how many values the vault holds before it forgets the
// least recently used half.
const DefaultLimit = 200_000

// hashLengths are the Placeholder hash lengths tried in turn: a value whose
// 8-character Placeholder already stands for another value of its Kind in
// its Caller scope takes the next length.
var hashLengths = []int{8, 12, 16, 20, 52}

// placeholderPattern matches a Placeholder exactly as Veil writes it.
var placeholderPattern = regexp.MustCompile(`\{\{[A-Z][A-Z0-9_]*_(?:[a-z2-7]{52}|[a-z2-7]{20}|[a-z2-7]{16}|[a-z2-7]{12}|[a-z2-7]{8})\}\}`)

// PlaceholderSpans returns the byte spans of the Placeholders already in text.
func PlaceholderSpans(text string) [][]int {
	if !strings.Contains(text, "{{") {
		return nil
	}
	return placeholderPattern.FindAllStringIndex(text, -1)
}

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// KnownMinLen is the shortest value masked wherever it reappears. Shorter
// values would turn up by chance in unrelated text.
const KnownMinLen = 8

type slot struct {
	scope, placeholder string
}

type entry struct {
	kind  string
	value string
	used  atomic.Uint64
}

// Vault holds Placeholders and their values, partitioned by Caller scope.
type Vault struct {
	key   []byte
	limit int
	clock atomic.Uint64

	mu      sync.RWMutex
	entries map[slot]*entry
	known   map[string]*knownIndex
	scopes  map[string]int
}

// New returns an empty vault minting Placeholders under key.
func New(key []byte, limit int) *Vault {
	if limit <= 0 {
		limit = DefaultLimit
	}
	return &Vault{
		key:     append([]byte(nil), key...),
		limit:   limit,
		entries: make(map[slot]*entry),
		known:   make(map[string]*knownIndex),
		scopes:  make(map[string]int),
	}
}

// Placeholder returns the Placeholder for value in scope, recording it so it
// restores.
func (v *Vault) Placeholder(scope, kind, value string) string {
	mac := hmac.New(sha256.New, v.key)
	mac.Write([]byte(scope))
	mac.Write([]byte{0})
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	hash := strings.ToLower(encoding.EncodeToString(mac.Sum(nil)))

	v.mu.Lock()
	defer v.mu.Unlock()
	for _, n := range hashLengths {
		p := "{{" + kind + "_" + hash[:n] + "}}"
		e, ok := v.entries[slot{scope, p}]
		if !ok {
			v.add(scope, p, kind, value)
			return p
		}
		if e.kind == kind && e.value == value {
			e.used.Store(v.clock.Add(1))
			return p
		}
	}
	// Every length is taken by another value: a full 256-bit collision.
	panic("vault: placeholder hash collided at every length")
}

// Lookup returns the value placeholder stands for in scope.
func (v *Vault) Lookup(scope, placeholder string) (string, bool) {
	v.mu.RLock()
	e, ok := v.entries[slot{scope, placeholder}]
	v.mu.RUnlock()
	if !ok {
		return "", false
	}
	e.used.Store(v.clock.Add(1))
	return e.value, true
}

// HasScope reports whether scope has any Placeholder to restore.
func (v *Vault) HasScope(scope string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.scopes[scope] > 0
}

// Len returns how many values the vault holds.
func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.entries)
}

// add records a new Placeholder; v.mu is held.
func (v *Vault) add(scope, placeholder, kind, value string) {
	if len(v.entries) >= v.limit {
		v.evict()
	}
	e := &entry{kind: kind, value: value}
	e.used.Store(v.clock.Add(1))
	v.entries[slot{scope, placeholder}] = e
	v.scopes[scope]++
	if len(value) >= KnownMinLen {
		idx := v.known[scope]
		if idx == nil {
			idx = newKnownIndex()
			v.known[scope] = idx
		}
		idx.add(kind, value)
	}
}

// evict forgets the least recently used half of the values and rebuilds the
// known-value indexes from what is left; v.mu is held.
func (v *Vault) evict() {
	type aged struct {
		slot slot
		used uint64
	}
	all := make([]aged, 0, len(v.entries))
	for s, e := range v.entries {
		all = append(all, aged{s, e.used.Load()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].used < all[j].used })
	for _, a := range all[:len(all)/2] {
		delete(v.entries, a.slot)
		if v.scopes[a.slot.scope]--; v.scopes[a.slot.scope] == 0 {
			delete(v.scopes, a.slot.scope)
		}
	}
	v.known = make(map[string]*knownIndex)
	for s, e := range v.entries {
		if len(e.value) < KnownMinLen {
			continue
		}
		idx := v.known[s.scope]
		if idx == nil {
			idx = newKnownIndex()
			v.known[s.scope] = idx
		}
		idx.add(e.kind, e.value)
	}
}

// Match is one occurrence of a known value in a text.
type Match struct {
	Start, End int
	Kind       string
}

// KnownMatches finds the Known values of scope in text, longest first at each
// position, never overlapping.
func (v *Vault) KnownMatches(scope, text string) []Match {
	v.mu.RLock()
	defer v.mu.RUnlock()
	idx := v.known[scope]
	if idx == nil {
		return nil
	}
	return idx.find(text)
}

// knownIndex finds known values in a text with one table lookup per byte: a
// bitset of the 4-byte grams that start a value rules out almost every
// position, and the rest are looked up by their first 8 bytes.
type knownIndex struct {
	grams  []uint64
	byHead map[string][]known
}

type known struct {
	kind, value string
}

const gramBits = 18

func newKnownIndex() *knownIndex {
	return &knownIndex{grams: make([]uint64, 1<<gramBits/64), byHead: make(map[string][]known)}
}

func gram(s string) uint32 {
	g := uint32(s[0]) | uint32(s[1])<<8 | uint32(s[2])<<16 | uint32(s[3])<<24
	return (g * 2654435761) >> (32 - gramBits)
}

func (k *knownIndex) add(kind, value string) {
	head := value[:KnownMinLen]
	for _, c := range k.byHead[head] {
		if c.value == value {
			return
		}
	}
	g := gram(value)
	k.grams[g/64] |= 1 << (g % 64)
	list := append(k.byHead[head], known{kind, value})
	// Longest first, so the longest known value wins at a position.
	sort.SliceStable(list, func(i, j int) bool { return len(list[i].value) > len(list[j].value) })
	k.byHead[head] = list
}

func (k *knownIndex) find(text string) []Match {
	var out []Match
	for i := 0; i+KnownMinLen <= len(text); i++ {
		g := gram(text[i:])
		if k.grams[g/64]&(1<<(g%64)) == 0 {
			continue
		}
		for _, c := range k.byHead[text[i:i+KnownMinLen]] {
			if strings.HasPrefix(text[i:], c.value) {
				out = append(out, Match{Start: i, End: i + len(c.value), Kind: c.kind})
				i += len(c.value) - 1
				break
			}
		}
	}
	return out
}
