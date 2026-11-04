package main

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
	"github.com/GarlandQian/cpa-plugin-veil/internal/vault"
)

const streamIdleTimeout = 10 * time.Minute

// streamCall is the host-independent input to streamed Restore. The adapter
// only identifies the header-init call and supplies the bodies the host gave.
type streamCall struct {
	scope, requestID  string
	requestBody, body []byte
	index             int
	init              bool
}

// streamRestorer owns matching, sequencing, Held tails and once-only finish.
// Entries never escape it. Unrelated streams can process chunks concurrently.
type streamRestorer struct {
	mu        sync.Mutex
	streams   map[[sha256.Size]byte][]*streamEntry
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
	return &streamRestorer{streams: make(map[[sha256.Size]byte][]*streamEntry), now: time.Now, vault: v, restorer: restore.New(v)}
}

// chunk returns the bytes to send, including the original bytes for a no-op.
// finish is used only on init, and called on completion, replacement, expiry
// or close. Empty payloads still advance the expected chunk index on CPA v8.
func (r *streamRestorer) chunk(c streamCall, finish func(*restore.Tally)) []byte {
	key, unique := requestKey(c.scope, c.requestID, c.requestBody)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return c.body
	}
	now := r.now()
	r.sweep(now)
	if c.init {
		defer r.mu.Unlock()
		if !r.vault.HasScope(c.scope) {
			return c.body
		}
		entries := r.streams[key]
		live := entries[:0]
		for _, e := range entries {
			e.mu.Lock()
			if unique {
				e.done()
			} else if !e.ended {
				e.stream.StopHolding()
				// Without IDs, chunks from these streams cannot be attributed
				// reliably. Drop both tallies rather than assign one to the other.
				e.finish = nil
				live = append(live, e)
			}
			e.mu.Unlock()
		}
		if len(live) > 0 {
			finish = nil
		}
		r.streams[key] = append(live, &streamEntry{stream: r.restorer.NewStream(c.scope, len(live) == 0), seen: now, finish: finish})
		return c.body
	}
	var entry *streamEntry
	for _, e := range r.streams[key] {
		if e.next != c.index {
			continue
		}
		e.mu.Lock()
		if e.ended {
			e.mu.Unlock()
			continue
		}
		e.next++
		e.seen = now
		entry = e
		break
	}
	r.mu.Unlock()
	if entry == nil {
		if len(c.body) == 0 || !r.vault.HasScope(c.scope) {
			return c.body
		}
		out, _ := r.restorer.NewStream(c.scope, false).Chunk(c.body)
		return out
	}
	// Release the entry even on a malformed-frame panic caught by the adapter.
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
		live := r.streams[key][:0]
		for _, e := range r.streams[key] {
			if e != entry {
				live = append(live, e)
			}
		}
		if len(live) == 0 {
			delete(r.streams, key)
		} else {
			r.streams[key] = live
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
	for key, entries := range r.streams {
		live := entries[:0]
		for _, e := range entries {
			if now.Sub(e.seen) < streamIdleTimeout {
				live = append(live, e)
				continue
			}
			e.mu.Lock()
			e.done()
			e.mu.Unlock()
		}
		if len(live) == 0 {
			delete(r.streams, key)
		} else {
			r.streams[key] = live
		}
	}
}

func (r *streamRestorer) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, entries := range r.streams {
		for _, e := range entries {
			e.mu.Lock()
			e.done()
			e.mu.Unlock()
		}
	}
	r.streams = nil
}
