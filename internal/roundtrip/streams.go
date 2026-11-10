package roundtrip

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

const streamIdleTimeout = 10 * time.Minute

// streamCall is one call about a stream: the one that opens it, or a chunk.
type streamCall struct {
	scope, requestID string
	body             []byte
	index            int
	init             bool
}

// streamRestorer owns matching, sequencing, Held tails and once-only finish.
// A stream is known by its request's ID; a chunk that names no request, or
// one whose stream Veil does not have, is restored on its own, with no Held
// tail. Entries never escape it. Unrelated streams can process chunks
// concurrently.
type streamRestorer struct {
	mu        sync.Mutex
	streams   map[[sha256.Size]byte]*streamEntry
	lastSweep time.Time
	now       func() time.Time
	closed    bool
	vault     *vault.Vault
	restorer  *restore.Restorer
}

type streamEntry struct {
	// mu guards Stream and finish; registry fields next/seen use the parent
	// mutex. Always acquire the parent first when both are needed.
	mu     sync.Mutex
	stream *restore.Stream
	finish func(*restore.Tally)
	ended  bool
	next   int
	seen   time.Time
}

func (e *streamEntry) done() {
	if e.ended {
		return
	}
	e.ended = true
	if e.finish != nil {
		e.finish(e.stream.Tally())
		e.finish = nil
	}
}

func newStreamRestorer(v *vault.Vault) *streamRestorer {
	return &streamRestorer{streams: make(map[[sha256.Size]byte]*streamEntry), now: time.Now, vault: v, restorer: restore.New(v)}
}

// chunk returns the bytes to send, including the original bytes for a no-op.
// finish is used only on init, and called on completion, replacement, expiry
// or close. Empty payloads still advance the expected chunk index.
func (r *streamRestorer) chunk(c streamCall, finish func(*restore.Tally)) []byte {
	key := requestKey(c.scope, c.requestID)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return c.body
	}
	now := r.now()
	r.sweep(now)
	if c.init {
		defer r.mu.Unlock()
		if c.requestID == "" || !r.vault.HasScope(c.scope) {
			return c.body
		}
		if e := r.streams[key]; e != nil {
			e.mu.Lock()
			e.done()
			e.mu.Unlock()
		}
		r.streams[key] = &streamEntry{stream: r.restorer.NewStream(c.scope, true), seen: now, finish: finish}
		return c.body
	}
	var entry *streamEntry
	if e := r.streams[key]; c.requestID != "" && e != nil && e.next == c.index {
		e.mu.Lock()
		if e.ended {
			e.mu.Unlock()
		} else {
			e.next++
			e.seen = now
			entry = e
		}
	}
	r.mu.Unlock()
	if entry == nil {
		if len(c.body) == 0 || !r.vault.HasScope(c.scope) {
			return c.body
		}
		out, _ := r.restorer.NewStream(c.scope, false).Chunk(c.body)
		return out
	}
	// Release the entry even on a malformed-frame panic the caller recovers.
	out, done := func() ([]byte, bool) {
		defer entry.mu.Unlock()
		if len(c.body) == 0 {
			return c.body, false
		}
		out, done := entry.stream.Chunk(c.body)
		if done {
			entry.done()
		}
		return out, done
	}()
	if done {
		r.mu.Lock()
		if r.streams[key] == entry {
			delete(r.streams, key)
		}
		r.mu.Unlock()
	}
	return out
}

// sweep runs under mu, at most once a minute when traffic arrives.
func (r *streamRestorer) sweep(now time.Time) {
	if now.Sub(r.lastSweep) < time.Minute {
		return
	}
	r.lastSweep = now
	for key, e := range r.streams {
		if now.Sub(e.seen) < streamIdleTimeout {
			continue
		}
		e.mu.Lock()
		e.done()
		e.mu.Unlock()
		delete(r.streams, key)
	}
}

func (r *streamRestorer) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, e := range r.streams {
		e.mu.Lock()
		e.done()
		e.mu.Unlock()
	}
	r.streams = nil
}
