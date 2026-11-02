// Package jsontree parses a JSON document into a tree of byte spans, so a
// caller can rewrite chosen strings and copy every other byte through as it
// was: key order, number spelling, escapes and whitespace all survive.
//
// Decoding into map[string]any and encoding again would reorder keys, turn
// large integers into floats and re-escape HTML, and would copy every base64
// image through Go values on the way.
package jsontree

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

// Kind is the JSON type of a Value.
type Kind uint8

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// maxDepth bounds nesting, as encoding/json does, so a hostile body cannot
// exhaust the stack.
const maxDepth = 10000

// Value is one JSON value and its span in the source.
type Value struct {
	Kind    Kind
	Start   int // first byte of the value, the opening quote for a string
	End     int // one past the last byte
	Members []Member
	Items   []*Value
	escaped bool // a string holding a backslash escape
}

// Member is one key of an object, in document order.
type Member struct {
	Key   string
	Value *Value
}

// Get returns the value of the last member named key, as JSON decoders read
// a duplicated key, or nil.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	for i := len(v.Members) - 1; i >= 0; i-- {
		if v.Members[i].Key == key {
			return v.Members[i].Value
		}
	}
	return nil
}

// All returns the value of every member named key, duplicates included.
func (v *Value) All(key string) []*Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	var out []*Value
	for _, m := range v.Members {
		if m.Key == key {
			out = append(out, m.Value)
		}
	}
	return out
}

// Doc is a parsed document and the string replacements made to it.
type Doc struct {
	Root  *Value
	src   []byte
	edits []edit
}

type edit struct {
	start, end int
	text       []byte
}

// Parse parses src, which must be exactly one JSON value.
func Parse(src []byte) (*Doc, error) {
	p := &parser{src: src}
	p.space()
	root, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(src) {
		return nil, p.fail("trailing data")
	}
	return &Doc{Root: root, src: src}, nil
}

// Text returns the decoded text of a string value.
func (d *Doc) Text(v *Value) (string, bool) {
	if v == nil || v.Kind != String {
		return "", false
	}
	if !v.escaped {
		return string(d.src[v.Start+1 : v.End-1]), true
	}
	var s string
	if err := json.Unmarshal(d.src[v.Start:v.End], &s); err != nil {
		return "", false
	}
	return s, true
}

// Raw returns the source bytes of v as they were written.
func (d *Doc) Raw(v *Value) string {
	return string(d.src[v.Start:v.End])
}

// ResetEdits drops every replacement made so far.
func (d *Doc) ResetEdits() {
	d.edits = nil
}

// IsTrue reports whether v is the literal true.
func (d *Doc) IsTrue(v *Value) bool {
	return v != nil && v.Kind == Bool && d.src[v.Start] == 't'
}

// SetString replaces the string value v with text.
func (d *Doc) SetString(v *Value, text string) {
	d.edits = append(d.edits, edit{start: v.Start, end: v.End, text: AppendString(nil, text)})
}

// Changed reports whether any value was replaced.
func (d *Doc) Changed() bool {
	return len(d.edits) > 0
}

// Bytes returns the document with every replacement applied.
func (d *Doc) Bytes() []byte {
	if len(d.edits) == 0 {
		return d.src
	}
	sort.Slice(d.edits, func(i, j int) bool { return d.edits[i].start < d.edits[j].start })
	size := len(d.src)
	for _, e := range d.edits {
		size += len(e.text) - (e.end - e.start)
	}
	out := make([]byte, 0, size)
	prev := 0
	for _, e := range d.edits {
		out = append(out, d.src[prev:e.start]...)
		out = append(out, e.text...)
		prev = e.end
	}
	return append(out, d.src[prev:]...)
}

// AppendString appends s as a JSON string. Unlike encoding/json it leaves
// <, > and & alone; invalid UTF-8 becomes U+FFFD as it does there.
func AppendString(dst []byte, s string) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			switch c {
			case '"', '\\':
				dst = append(dst, '\\', c)
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, `�`...)
			i++
			start = i
			continue
		}
		i += size
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

var errSyntax = errors.New("invalid JSON")

type parser struct {
	src []byte
	pos int
}

func (p *parser) fail(what string) error {
	return fmt.Errorf("%w: %s at byte %d", errSyntax, what, p.pos)
}

func (p *parser) space() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (*Value, error) {
	if p.pos >= len(p.src) {
		return nil, p.fail("unexpected end")
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.string()
	case c == 't':
		return p.literal("true", Bool)
	case c == 'f':
		return p.literal("false", Bool)
	case c == 'n':
		return p.literal("null", Null)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.fail("unexpected character")
	}
}

func (p *parser) literal(word string, kind Kind) (*Value, error) {
	start := p.pos
	if len(p.src)-p.pos < len(word) || string(p.src[p.pos:p.pos+len(word)]) != word {
		return nil, p.fail("bad literal")
	}
	p.pos += len(word)
	return &Value{Kind: kind, Start: start, End: p.pos}, nil
}

func (p *parser) digits() int {
	n := 0
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
		n++
	}
	return n
}

func (p *parser) number() (*Value, error) {
	start := p.pos
	if p.src[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos < len(p.src) && p.src[p.pos] == '0':
		p.pos++
	case p.digits() == 0:
		return nil, p.fail("bad number")
	}
	if p.pos < len(p.src) && p.src[p.pos] == '.' {
		p.pos++
		if p.digits() == 0 {
			return nil, p.fail("bad fraction")
		}
	}
	if p.pos < len(p.src) && (p.src[p.pos] == 'e' || p.src[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.src) && (p.src[p.pos] == '+' || p.src[p.pos] == '-') {
			p.pos++
		}
		if p.digits() == 0 {
			return nil, p.fail("bad exponent")
		}
	}
	return &Value{Kind: Number, Start: start, End: p.pos}, nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func (p *parser) string() (*Value, error) {
	v := &Value{Kind: String, Start: p.pos}
	p.pos++
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			v.End = p.pos
			return v, nil
		case c == '\\':
			v.escaped = true
			p.pos++
			if p.pos >= len(p.src) {
				return nil, p.fail("unterminated escape")
			}
			switch p.src[p.pos] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				p.pos++
			case 'u':
				if len(p.src)-p.pos < 5 || !isHex(p.src[p.pos+1]) || !isHex(p.src[p.pos+2]) || !isHex(p.src[p.pos+3]) || !isHex(p.src[p.pos+4]) {
					return nil, p.fail("bad unicode escape")
				}
				p.pos += 5
			default:
				return nil, p.fail("bad escape")
			}
		case c < 0x20:
			return nil, p.fail("control character in string")
		default:
			p.pos++
		}
	}
	return nil, p.fail("unterminated string")
}

func (p *parser) array(depth int) (*Value, error) {
	if depth > maxDepth {
		return nil, p.fail("nested too deep")
	}
	v := &Value{Kind: Array, Start: p.pos}
	p.pos++
	p.space()
	if p.pos < len(p.src) && p.src[p.pos] == ']' {
		p.pos++
		v.End = p.pos
		return v, nil
	}
	for {
		p.space()
		item, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		v.Items = append(v.Items, item)
		p.space()
		if p.pos >= len(p.src) {
			return nil, p.fail("unterminated array")
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			v.End = p.pos
			return v, nil
		default:
			return nil, p.fail("expected , or ]")
		}
	}
}

func (p *parser) object(depth int) (*Value, error) {
	if depth > maxDepth {
		return nil, p.fail("nested too deep")
	}
	v := &Value{Kind: Object, Start: p.pos}
	p.pos++
	p.space()
	if p.pos < len(p.src) && p.src[p.pos] == '}' {
		p.pos++
		v.End = p.pos
		return v, nil
	}
	for {
		p.space()
		if p.pos >= len(p.src) || p.src[p.pos] != '"' {
			return nil, p.fail("expected key")
		}
		keyValue, err := p.string()
		if err != nil {
			return nil, err
		}
		key := string(p.src[keyValue.Start+1 : keyValue.End-1])
		if keyValue.escaped {
			if err := json.Unmarshal(p.src[keyValue.Start:keyValue.End], &key); err != nil {
				return nil, p.fail("bad key")
			}
		}
		p.space()
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return nil, p.fail("expected :")
		}
		p.pos++
		p.space()
		member, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		v.Members = append(v.Members, Member{Key: key, Value: member})
		p.space()
		if p.pos >= len(p.src) {
			return nil, p.fail("unterminated object")
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			v.End = p.pos
			return v, nil
		default:
			return nil, p.fail("expected , or }")
		}
	}
}
