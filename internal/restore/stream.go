package restore

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/GarlandQian/cpa-plugin-veil/internal/fields"
	"github.com/GarlandQian/cpa-plugin-veil/internal/jsontree"
)

// Stream restores the Placeholders of one streamed response, chunk by chunk.
//
// A model streams a Placeholder in pieces, so a field ending in what could be
// the start of one is a Held tail: the event carrying it is held back until
// the next event shows whether the same field continues. If it does, the held
// event goes out without the tail and the tail is restored together with
// what follows; if not, the held event goes out as it came. Ping events pass
// a held event; any other event releases it, and an event after which its
// block cannot continue is never held.
//
// The host hands a passthrough stream over one SSE line per chunk, so an
// event line waits for its data line and the event goes out whole. A Stream
// without holding restores line by line and keeps no state, for a chunk Veil
// cannot place in a stream.
type Stream struct {
	r     *Restorer
	scope string
	hold  bool

	eventLine    []byte // an event line waiting for its data line
	held         *heldEvent
	swallowBlank bool // the held event's blank line has yet to arrive

	// tally counts what the events that went out had restored.
	tally Tally
}

type heldEvent struct {
	eventLine []byte
	full      []byte // the data restored with its tails left as they came
	cut       []byte // the data restored without its tails
	tails     map[string]string
	// fullTally and cutTally count what full and cut restored; only the one
	// that goes out counts for the stream
	fullTally, cutTally *Tally
}

// NewStream returns a Stream for a response in scope.
func (r *Restorer) NewStream(scope string, hold bool) *Stream {
	return &Stream{r: r, scope: scope, hold: hold}
}

// Tally returns what the events delivered so far had restored.
func (s *Stream) Tally() *Tally {
	var t Tally
	t.Add(&s.tally)
	return &t
}

// Chunk returns what to deliver in place of chunk, which may be nothing, and
// whether the stream has ended.
func (s *Stream) Chunk(chunk []byte) (out []byte, done bool) {
	if s.hold && s.eventLine == nil {
		if t := bytes.TrimSpace(chunk); len(t) > 0 && t[0] == '{' {
			if ev := s.parse(t, ""); ev.doc != nil {
				return s.bare(ev, chunk)
			}
		}
	}
	var b bytes.Buffer
	for len(chunk) > 0 {
		line := chunk
		if i := bytes.IndexByte(chunk, '\n'); i >= 0 {
			line = chunk[:i+1]
		}
		chunk = chunk[len(line):]
		if s.line(&b, line) {
			done = true
		}
	}
	return b.Bytes(), done
}

// line handles one line, line ending included, and reports the stream's end.
func (s *Stream) line(b *bytes.Buffer, line []byte) bool {
	newLine(b)
	content := bytes.TrimRight(line, "\r\n")
	ending := line[len(content):]
	payload, isData := bytes.CutPrefix(content, []byte("data:"))
	switch {
	case !s.hold:
		if isData {
			b.WriteString("data:")
			b.Write(s.restoreData(payload, "", false).out)
		} else {
			s.raw(b, content)
		}
		b.Write(ending)
		return false
	case bytes.HasPrefix(content, []byte("event:")):
		b.Write(s.eventLine)
		s.eventLine = append([]byte(nil), line...)
		return false
	case isData:
		eventLine := s.eventLine
		s.eventLine = nil
		return s.event(b, eventLine, payload, ending)
	case len(content) == 0:
		if s.swallowBlank {
			s.swallowBlank = false
			return false
		}
		b.Write(s.eventLine)
		s.eventLine = nil
		b.Write(line)
		return false
	default:
		// id:, retry:, comments, and anything that is not SSE.
		s.raw(b, content)
		b.Write(ending)
		return false
	}
}

// event handles a data line while holding is on.
func (s *Stream) event(b *bytes.Buffer, eventLine, payload, ending []byte) bool {
	name := strings.TrimSpace(strings.TrimPrefix(strings.TrimRight(string(eventLine), "\r\n"), "event:"))
	ev := s.parse(payload, name)
	if ev.doc == nil {
		s.release(b)
		writeLine(b, eventLine)
		b.WriteString("data:")
		s.raw(b, payload)
		b.Write(ending)
		return strings.TrimSpace(string(payload)) == "[DONE]"
	}
	if ev.typ == "ping" || name == "ping" {
		writeLine(b, eventLine)
		b.WriteString("data:")
		b.Write(payload)
		b.Write(ending)
		return false
	}

	if eventLine, data, ok := s.settle(ev); ok {
		s.render(b, eventLine, data)
	}

	r := s.restore(ev, !isFinal(ev.doc, ev.typ))
	if len(r.tails) > 0 {
		s.held = &heldEvent{eventLine: eventLine, full: r.full, cut: r.cut, tails: r.tails, fullTally: r.fullTally, cutTally: r.cutTally}
		s.swallowBlank = true
		return false
	}
	s.tally.Add(r.fullTally)
	writeLine(b, eventLine)
	b.WriteString("data:")
	if r.full == nil {
		b.Write(payload)
	} else {
		b.WriteByte(' ')
		b.Write(r.full)
	}
	b.Write(ending)
	return streamEnd(ev.typ)
}

// bare handles a chunk that is one JSON event with no SSE framing: the
// OpenAI chat and Gemini handlers write each chunk as "data: <chunk>\n\n"
// themselves. A held event and the next one go out in one chunk as
// "<held>\n\ndata: <next>", which the handler's framing turns into two
// events. Their stream ends after an event with a finish reason, which is
// never held, so nothing held is left when it does.
func (s *Stream) bare(ev streamEvent, chunk []byte) ([]byte, bool) {
	var payloads [][]byte
	if _, data, ok := s.settle(ev); ok {
		payloads = append(payloads, data)
	}
	final := isFinal(ev.doc, ev.typ)
	r := s.restore(ev, !final)
	if len(r.tails) == 0 {
		s.tally.Add(r.fullTally)
	}
	switch {
	case len(r.tails) > 0:
		s.held = &heldEvent{full: r.full, cut: r.cut, tails: r.tails, fullTally: r.fullTally, cutTally: r.cutTally}
	case r.full != nil:
		payloads = append(payloads, r.full)
	default:
		if len(payloads) == 0 {
			return chunk, final
		}
		payloads = append(payloads, bytes.TrimSpace(chunk))
	}
	return bytes.Join(payloads, []byte("\n\ndata: ")), final
}

// settle decides the held event, if any, now the next event ev is here. If ev
// continues every field held, the held event goes out without its tails and
// ev takes them; if not, it goes out as it came. It returns what to write.
func (s *Stream) settle(ev streamEvent) (eventLine, data []byte, ok bool) {
	held := s.held
	if held == nil {
		return nil, nil, false
	}
	s.held = nil
	for ctx := range held.tails {
		if ev.byCtx[ctx] == nil {
			s.tally.Add(held.fullTally)
			return held.eventLine, held.full, true
		}
	}
	s.tally.Add(held.cutTally)
	for ctx, tail := range held.tails {
		ev.byCtx[ctx].Text = tail + ev.byCtx[ctx].Text
	}
	return held.eventLine, held.cut, true
}

// release writes out a held event and a waiting event line.
func (s *Stream) release(b *bytes.Buffer) {
	if s.held != nil {
		s.render(b, s.held.eventLine, s.held.full)
		s.tally.Add(s.held.fullTally)
		s.held = nil
		s.swallowBlank = false
	}
	b.Write(s.eventLine)
	s.eventLine = nil
}

// newLine starts a new line in b. The host may hand a stream over one line
// per chunk without its line ending (CPA v8's Codex path does), and lines
// Veil held and writes out together must not run into one another, as
// "event: xdata: {...}" would.
func newLine(b *bytes.Buffer) {
	if n := b.Len(); n > 0 && b.Bytes()[n-1] != '\n' {
		b.WriteByte('\n')
	}
}

// writeLine writes a held line, which may have come without its ending, and
// starts the next one.
func writeLine(b *bytes.Buffer, line []byte) {
	if len(line) == 0 {
		return
	}
	newLine(b)
	b.Write(line)
	newLine(b)
}

// render writes a held event, ending it with the blank line its original
// went out without.
func (s *Stream) render(b *bytes.Buffer, eventLine, data []byte) {
	writeLine(b, eventLine)
	b.WriteString("data: ")
	b.Write(data)
	b.WriteString("\n\n")
}

// raw restores a line that is not a JSON data line, such as a piece of a
// Gemini JSON array stream; values are escaped for the JSON they land in.
func (s *Stream) raw(b *bytes.Buffer, content []byte) {
	if out, ok := s.r.replace(s.scope, string(content), true, &s.tally); ok {
		b.WriteString(out)
		return
	}
	b.Write(content)
}

// streamEvent is the JSON of one data line and its fields by stream position.
type streamEvent struct {
	doc   *jsontree.Doc
	set   *fields.Set
	typ   string
	byCtx map[string]*fields.Field
}

func (s *Stream) parse(payload []byte, name string) streamEvent {
	doc, err := jsontree.Parse(bytes.TrimSpace(payload))
	if err != nil || doc.Root.Kind != jsontree.Object {
		return streamEvent{}
	}
	ev := streamEvent{doc: doc, set: fields.Walk(doc), byCtx: map[string]*fields.Field{}}
	ev.typ, _ = doc.Text(doc.Root.Get("type"))
	root := name + "|" + ev.typ
	for _, key := range []string{"index", "output_index", "content_index", "item_id"} {
		if v := doc.Root.Get(key); v != nil {
			root += "|" + doc.Raw(v)
		}
	}
	for _, f := range ev.set.Fields {
		if f.Doc == doc {
			ev.byCtx[root+"|"+f.Ctx] = f
		}
	}
	return ev
}

// restoreData restores one data line without holding; out is the payload
// to write after "data:".
func (s *Stream) restoreData(payload []byte, name string, hold bool) (r restored) {
	ev := s.parse(payload, name)
	if ev.doc == nil {
		var b bytes.Buffer
		s.raw(&b, payload)
		return restored{out: b.Bytes()}
	}
	r = s.restore(ev, hold)
	s.tally.Add(r.fullTally)
	if r.full == nil {
		r.out = payload
	} else {
		r.out = append([]byte{' '}, r.full...)
	}
	return r
}

type restored struct {
	// fullTally and cutTally count what full and cut restored
	fullTally, cutTally *Tally
	full                []byte // nil when nothing changed
	cut                 []byte
	tails               map[string]string
	out                 []byte
}

// restore restores the fields of one event. With hold, a top-level field that
// ends in what may start a Placeholder yields a tail: full keeps the tail as
// it came and cut leaves it out.
func (s *Stream) restore(ev streamEvent, hold bool) restored {
	type top struct {
		f          *fields.Field
		original   string
		full, cut  string
		tail, hits bool
	}
	var tops []top
	r := restored{fullTally: &Tally{}, cutTally: &Tally{}}
	// strings inside a complete JSON argument go out in full and cut alike
	var nested Tally
	ctxOf := map[*fields.Field]string{}
	for ctx, f := range ev.byCtx {
		ctxOf[f] = ctx
	}
	for _, f := range ev.set.Fields {
		if f.Doc != ev.doc {
			// A string inside a complete JSON argument.
			if out, ok := s.r.replace(s.scope, f.Text, false, &nested); ok {
				f.Doc.SetString(f.Value, out)
			}
			continue
		}
		escape := isJSONFragment(f.Path, ev.typ)
		t := top{f: f, full: f.Text}
		t.original, _ = ev.doc.Text(f.Value)
		var full Tally
		if out, ok := s.r.replace(s.scope, f.Text, escape, &full); ok {
			t.full = out
		}
		r.fullTally.Add(&full)
		if at := s.partialTail(f.Text); hold && at >= 0 {
			t.tail = true
			t.cut = f.Text[:at]
			var cut Tally
			if out, ok := s.r.replace(s.scope, t.cut, escape, &cut); ok {
				t.cut = out
			}
			r.cutTally.Add(&cut)
			if r.tails == nil {
				r.tails = map[string]string{}
			}
			r.tails[ctxOf[f]] = f.Text[at:]
		} else {
			r.cutTally.Add(&full)
		}
		tops = append(tops, t)
	}
	r.fullTally.Add(&nested)
	r.cutTally.Add(&nested)

	apply := func(cut bool) {
		ev.set.Commit()
		for _, t := range tops {
			text := t.full
			if cut && t.tail {
				text = t.cut
			}
			if text != t.original {
				ev.doc.SetString(t.f.Value, text)
			}
		}
	}
	apply(false)
	if !ev.doc.Changed() && r.tails == nil {
		return r
	}
	r.full = ev.doc.Bytes()
	if r.tails != nil {
		ev.doc.ResetEdits()
		apply(true)
		r.cut = ev.doc.Bytes()
	}
	return r
}

// isJSONFragment reports a field holding a piece of a tool call's JSON
// arguments, whose restored values must be escaped for JSON.
func isJSONFragment(path, typ string) bool {
	last := path
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		last = path[i+1:]
	}
	return last == "arguments" || last == "partial_json" || (last == "delta" && strings.Contains(typ, "arguments"))
}

// streamEnd reports an event type after which its stream has nothing more,
// however it ended.
func streamEnd(typ string) bool {
	switch typ {
	case "message_stop", "response.completed", "response.failed", "response.incomplete":
		return true
	}
	return false
}

// isFinal reports an event after which no text of its block follows, so
// nothing may be held back from it: nothing would come to release it.
func isFinal(doc *jsontree.Doc, typ string) bool {
	if streamEnd(typ) {
		return true
	}
	for _, key := range []string{"choices", "candidates"} {
		list := doc.Root.Get(key)
		if list == nil || list.Kind != jsontree.Array {
			continue
		}
		for _, item := range list.Items {
			for _, reason := range []string{"finish_reason", "finishReason"} {
				if v := item.Get(reason); v != nil && v.Kind != jsontree.Null {
					return true
				}
			}
		}
	}
	return false
}

// maxTail is the longest text worth holding: a Placeholder with the longest
// hash, its kind and its braces.
const maxTail = 96

var openTail = regexp.MustCompile(`^\{\{?[ \t]*(?:[A-Za-z][A-Za-z0-9_]*)?[ \t]*\}?$`)

// partialTail returns where text ends in what may be the start of a
// Placeholder, or -1.
func (s *Stream) partialTail(text string) int {
	if s.r.vault.HasStandIns(s.scope) {
		if k := s.standInTail(text); k >= 0 {
			return k
		}
	}
	lo := len(text) - maxTail
	if lo < 0 {
		lo = 0
	}
	if i := strings.LastIndexByte(text[lo:], '{'); i >= 0 {
		i += lo
		if i > lo && text[i-1] == '{' {
			i--
		}
		if t := text[i:]; openTail.MatchString(t) && !strings.HasSuffix(t, "}}") {
			return i
		}
	}
	j := len(text)
	for j > lo && isWord(text[j-1]) {
		j--
	}
	if j == len(text) || (j > 0 && isWord(text[j-1])) {
		return -1
	}
	if s.mayStartToken(text[j:]) || s.r.vault.StandInPrefix(s.scope, text[j:]) {
		return j
	}
	return -1
}

// standInTail returns where text ends in what may be the start of a public
// IP address's Stand-in (public-ip-…), or -1.
func (s *Stream) standInTail(text string) int {
	const head = "public-ip-"
	for k := max(0, len(text)-len(head)-8); k < len(text); k++ {
		if k > 0 && (isWord(text[k-1]) || text[k-1] == '-') {
			continue
		}
		// A whole Stand-in at the end is held too: a letter after it would
		// make it part of a longer word.
		t := strings.ToLower(text[k:])
		if (strings.HasPrefix(head, t) || strings.HasPrefix(t, head) && len(t) <= len(head)+8) && s.r.vault.StandInPrefix(s.scope, t) {
			return k
		}
	}
	return -1
}

// mayStartToken reports whether word may grow into a bare Placeholder token:
// an upper-case prefix of a Kind, or a Kind followed by part of a hash.
func (s *Stream) mayStartToken(word string) bool {
	upper := strings.ToUpper(word)
	for _, kind := range s.r.vault.Kinds() {
		if strings.HasPrefix(kind, word) {
			return true
		}
		if rest, ok := strings.CutPrefix(upper, kind+"_"); ok && len(rest) < 8 &&
			strings.Trim(strings.ToLower(rest), "abcdefghijklmnopqrstuvwxyz234567") == "" {
			return true
		}
	}
	return false
}
