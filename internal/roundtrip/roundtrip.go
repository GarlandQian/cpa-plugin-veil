// Package roundtrip follows each Round trip from its request to the end of
// its response: which request a call of the Host is about, which Masking
// record is that request's, the order of a stream's chunks, and counting what
// the response put back, once.
//
// The Host names a request by its ID in every call about it, and a Round
// trip is known by that ID within its Caller scope. A call that names no
// request belongs to none: its response is still restored, a stream's chunks
// each on their own with no Held tail, and nothing is counted.
package roundtrip

import (
	"crypto/sha256"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

// Trips holds the Round trips of one instance, across its config reloads.
type Trips struct {
	links    *recordLinks
	streams  *streamRestorer
	restorer *restore.Restorer
}

// New returns Trips that restore from v.
func New(v *vault.Vault) *Trips {
	return &Trips{links: newRecordLinks(), streams: newStreamRestorer(v), restorer: restore.New(v)}
}

// Recorded tells of the Masking record a Pass of a request kept. The request's
// response adds what it put back to that record.
func (t *Trips) Recorded(scope, requestID string, ref records.Ref) {
	t.links.put(scope, requestID, ref)
}

// Respond returns a whole response with its Placeholders restored, or nil
// when it has none, and ends the Round trip: only a request's first response
// counts.
func (t *Trips) Respond(scope, requestID string, body []byte) []byte {
	ref, recorded := t.links.take(scope, requestID)
	if !recorded {
		return t.restorer.BodyTally(scope, body, nil)
	}
	tally := &restore.Tally{}
	out := t.restorer.BodyTally(scope, body, tally)
	ref.Restore(tally.Back, tally.Unrestored)
	return out
}

// Open starts the stream of a request's response, with the header-only call
// that comes before its chunks. Opening it again ends the stream it had.
func (t *Trips) Open(scope, requestID string) {
	var finish func(*restore.Tally)
	if ref, recorded := t.links.take(scope, requestID); recorded {
		finish = func(tally *restore.Tally) { ref.Restore(tally.Back, tally.Unrestored) }
	}
	t.streams.chunk(streamCall{scope: scope, requestID: requestID, init: true}, finish)
}

// Chunk returns what to send in place of one chunk of a streamed response,
// which may be nothing while a Held tail waits for what follows. index counts
// the chunks from 0, the empty ones too. The Round trip ends with the event
// that ends its stream, or when the stream has been idle too long.
func (t *Trips) Chunk(scope, requestID string, index int, body []byte) []byte {
	return t.streams.chunk(streamCall{scope: scope, requestID: requestID, body: body, index: index}, nil)
}

// Close ends every Round trip, counting what its stream had put back so far.
// Chunks that come later go through as they are.
func (t *Trips) Close() {
	t.streams.close()
}

// requestKey binds a Host request ID to its Caller scope.
func requestKey(scope, requestID string) (key [sha256.Size]byte) {
	h := sha256.New()
	h.Write([]byte("request\x00"))
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(requestID))
	h.Sum(key[:0])
	return key
}
