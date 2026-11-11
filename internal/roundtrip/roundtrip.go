// Package roundtrip follows each Round trip from its request to the end of
// its response: which request a call of the Host is about, the one Masking
// record of that request, the order of a stream's chunks, and counting what
// the response put back, once.
//
// The Host names a request by its ID in every call about it, and a Round trip
// is known by that ID within its Caller scope. A Pass before the Host picks a
// credential starts a Round trip; the Passes after it, one for each credential
// the Host tries, are the same Round trip, and so is the response. A
// connection that carries several requests in turn under one ID makes a Round
// trip of each.
//
// A Round trip ends, and counts what its response put back, with the whole
// response, with the event that ends its stream, with the next Round trip of
// its ID, when the Host says the request is complete, when no call has
// touched it for too long, or when the instance shuts down, whichever comes
// first.
//
// A call that names no request belongs to no Round trip. It is still masked
// and restored, a stream's chunks each on their own with no Held tail, and
// nothing is counted.
package roundtrip

import (
	"crypto/sha256"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// idleTimeout is how long a Round trip may go without a call before it is
// ended. The Host says when a request is complete, so this only bounds what a
// Host that did not would leave behind.
const idleTimeout = 10 * time.Minute

// leftMax is how many bodies a Round trip remembers its Passes having left:
// the one before the Host picks a credential and a few of those after.
const leftMax = 8

// Trips holds the Round trips of one instance, across its config reloads.
type Trips struct {
	mu        sync.Mutex
	byID      map[string][]*trip // a request ID's Round trips, one per Caller scope
	closed    bool
	lastSweep time.Time
	now       func() time.Time
	vault     *vault.Vault
	restorer  *restore.Restorer
}

// New returns Trips that restore from v.
func New(v *vault.Vault) *Trips {
	return &Trips{byID: make(map[string][]*trip), now: time.Now, vault: v, restorer: restore.New(v)}
}

// trip is one Round trip.
type trip struct {
	owner   *Trips
	scope   string
	touched atomic.Int64 // when a call last came for it

	// mu guards what follows. It is never taken with Trips.mu held.
	mu sync.Mutex

	// The request: its record, the values the record has, and the bodies a
	// Pass left as they are.
	ref      records.Ref
	recorded bool
	values   map[string]struct{}
	left     [][sha256.Size]byte

	// The response: stream is nil where there is nothing to restore or count.
	answered bool // a response began
	begun    bool // its stream began
	over     bool // its stream ended
	next     int  // the index of the chunk to come
	stream   *restore.Stream
	tally    restore.Tally // what the response put back before this stream
	settled  bool
}

// Pass is one time the Host hands Veil a request to mask.
type Pass struct {
	trip *trip // nil for a call that named no request
	came [sha256.Size]byte
}

// Pass tells of one time the Host hands Veil a request to mask. One before the
// Host picks a credential starts a Round trip, ending the one its request ID
// had; one after it belongs to the Round trip its request ID has.
func (t *Trips) Pass(scope, requestID string, beforeAuth bool) *Pass {
	r, old := t.trip(scope, requestID, true, beforeAuth)
	if old != nil {
		old.end()
	}
	return &Pass{trip: r}
}

// Left says whether an earlier Pass of the Round trip left exactly body, the
// body this Pass came with, which then needs no second look.
func (p *Pass) Left(body []byte) bool {
	r := p.trip
	if r == nil {
		return false
	}
	p.came = sha256.Sum256(body)
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.left, p.came)
}

// Leave tells what the Pass leaves, having looked at all of the body Left
// was asked about: masked, or that body as it came if masked is nil.
func (p *Pass) Leave(masked []byte) {
	r := p.trip
	if r == nil {
		return
	}
	sum := p.came
	if masked != nil {
		sum = sha256.Sum256(masked)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if slices.Contains(r.left, sum) {
		return
	}
	if len(r.left) >= leftMax {
		r.left = r.left[1:]
	}
	r.left = append(r.left, sum)
}

// Keep adds what the Pass found to the Round trip's Masking record in store:
// rec as the record if the Round trip has none, or else the Values of rec the
// record does not have yet, with Stopped if the Pass stopped the request. A
// Pass that found nothing keeps nothing, and neither does a nil store.
func (p *Pass) Keep(store *records.Store, rec records.Record) {
	if store == nil || (len(rec.Values) == 0 && rec.Stopped == "") {
		return
	}
	r := p.trip
	if r == nil {
		store.Add(rec)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.recorded {
		ref, ok := store.Add(rec)
		if !ok {
			return
		}
		r.ref, r.recorded = ref, true
		r.values = make(map[string]struct{}, len(rec.Values))
		for _, v := range rec.Values {
			r.values[v.Placeholder] = struct{}{}
		}
		return
	}
	more := records.Record{Stopped: rec.Stopped, Took: rec.Took}
	for _, v := range rec.Values {
		if _, has := r.values[v.Placeholder]; has {
			continue
		}
		r.values[v.Placeholder] = struct{}{}
		more.Values = append(more.Values, v)
		more.N += v.N
		if snip, ok := rec.Snips[v.Placeholder]; ok {
			if more.Snips == nil {
				more.Snips = map[string]string{}
			}
			more.Snips[v.Placeholder] = snip
		}
	}
	if len(more.Values) > 0 || more.Stopped != "" {
		r.ref.Append(more)
	}
}

// Respond returns a whole response with its Placeholders restored, or nil
// when it has none, and ends the Round trip: only a request's first response
// counts.
func (t *Trips) Respond(scope, requestID string, body []byte) []byte {
	r, _ := t.trip(scope, requestID, false, false)
	if r == nil {
		return t.restorer.BodyTally(scope, body, nil)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.settled || !r.recorded {
		return t.restorer.BodyTally(scope, body, nil)
	}
	out := t.restorer.BodyTally(scope, body, &r.tally)
	r.answered = true
	r.settle()
	return out
}

// Open starts the stream of a request's response, with the header-only call
// that comes before its chunks. Opening it again starts the stream over.
func (t *Trips) Open(scope, requestID string) {
	r, _ := t.trip(scope, requestID, true, false)
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.begin(0)
}

// Chunk returns what to send in place of one chunk of a streamed response,
// which may be nothing while a Held tail waits for what follows. index counts
// the chunks, the empty ones too: from 0 after Open, and from the first chunk
// that comes where a Round trip's stream was not opened, as on a connection
// the Host opened for an earlier one. A chunk out of that order is restored
// on its own.
func (t *Trips) Chunk(scope, requestID string, index int, body []byte) []byte {
	r, _ := t.trip(scope, requestID, false, false)
	if r == nil {
		return t.alone(scope, body)
	}
	// Release the Round trip even on a malformed-frame panic the caller
	// recovers.
	out, placed := func() ([]byte, bool) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.begun {
			r.begin(index)
		}
		if r.over || index != r.next {
			return nil, false
		}
		r.next++
		if r.stream == nil || len(body) == 0 {
			return body, true
		}
		out, done := r.stream.Chunk(body)
		if done {
			r.settle()
			r.over, r.stream = true, nil
		}
		return out, true
	}()
	if !placed {
		return t.alone(scope, body)
	}
	return out
}

// Complete tells that the Host is done with a request ID: its last Round trip
// ends, and nothing more will come for it.
func (t *Trips) Complete(requestID string) {
	t.mu.Lock()
	trips := t.byID[requestID]
	delete(t.byID, requestID)
	t.mu.Unlock()
	for _, r := range trips {
		r.end()
	}
}

// Close ends every Round trip. Calls that come later belong to none.
func (t *Trips) Close() {
	t.mu.Lock()
	all := t.byID
	t.byID, t.closed = nil, true
	t.mu.Unlock()
	for _, trips := range all {
		for _, r := range trips {
			r.end()
		}
	}
}

// trip finds the Round trip of a call. With create it makes one where there
// is none, and with restart it makes one in any case, returning the one it
// takes the place of for the caller to end. It is nil for a call that names
// no request and after Close.
func (t *Trips) trip(scope, requestID string, create, restart bool) (r, old *trip) {
	if requestID == "" {
		return nil, nil
	}
	now := t.now()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, nil
	}
	idle := t.sweep(now)
	trips := t.byID[requestID]
	at := slices.IndexFunc(trips, func(r *trip) bool { return r.scope == scope })
	switch {
	case at >= 0 && !restart:
		r = trips[at]
	case at >= 0:
		r, old = &trip{owner: t, scope: scope}, trips[at]
		trips[at] = r
	case create:
		r = &trip{owner: t, scope: scope}
		t.byID[requestID] = append(trips, r)
	}
	if r != nil {
		r.touched.Store(now.UnixNano())
	}
	t.mu.Unlock()
	for _, gone := range idle {
		gone.end()
	}
	return r, old
}

// sweep takes out the Round trips no call has touched for idleTimeout, for
// the caller to end once it has released mu, which is held. It runs at most
// once a minute, when a call comes.
func (t *Trips) sweep(now time.Time) (idle []*trip) {
	if now.Sub(t.lastSweep) < time.Minute {
		return nil
	}
	t.lastSweep = now
	before := now.Add(-idleTimeout).UnixNano()
	for id, trips := range t.byID {
		kept := trips[:0]
		for _, r := range trips {
			if r.touched.Load() > before {
				kept = append(kept, r)
			} else {
				idle = append(idle, r)
			}
		}
		if len(kept) == 0 {
			delete(t.byID, id)
		} else {
			t.byID[id] = kept
		}
	}
	return idle
}

// alone restores a chunk that has no place in a stream.
func (t *Trips) alone(scope string, body []byte) []byte {
	if len(body) == 0 || !t.vault.HasScope(scope) {
		return body
	}
	out, _ := t.restorer.NewStream(scope, false).Chunk(body)
	return out
}

// begin starts the stream of the response at the chunk next, keeping what a
// stream before it put back; mu is held.
func (r *trip) begin(next int) {
	if r.stream != nil {
		r.tally.Add(r.stream.Tally())
	}
	r.answered, r.begun, r.over, r.next, r.stream = true, true, false, next, nil
	if r.recorded || r.owner.vault.HasScope(r.scope) {
		r.stream = r.owner.restorer.NewStream(r.scope, true)
	}
}

// end ends the Round trip from outside its response.
func (r *trip) end() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settle()
}

// settle counts what the response put back in the Round trip's record, once,
// and only if a response began; mu is held.
func (r *trip) settle() {
	if r.settled {
		return
	}
	r.settled = true
	if !r.recorded || !r.answered {
		return
	}
	if r.stream != nil {
		r.tally.Add(r.stream.Tally())
	}
	r.ref.Restore(r.tally.Back, r.tally.Unrestored)
}
