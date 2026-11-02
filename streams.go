package main

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/restore"
)

// streamIdleTimeout is how long a stream may go without a chunk before Veil
// forgets it, which covers streams the client or upstream abandoned.
const streamIdleTimeout = 10 * time.Minute

// streamRegistry tells the chunks of concurrent streams apart. The host gives
// no stream ID, so a stream is known by its Caller scope and request body,
// and by the index of the chunk it expects next.
type streamRegistry struct {
	mu        sync.Mutex
	streams   map[[sha256.Size]byte][]*streamEntry
	lastSweep time.Time
}

type streamEntry struct {
	stream *restore.Stream
	next   int
	seen   time.Time
}

func newStreamRegistry() *streamRegistry {
	return &streamRegistry{streams: make(map[[sha256.Size]byte][]*streamEntry)}
}

// start registers a new stream. A second stream of the same scope and body
// while the first is live cannot be told apart from it chunk for chunk, so
// both stop holding and are restored line by line.
func (r *streamRegistry) start(key [sha256.Size]byte, open func(hold bool) *restore.Stream) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweep(now)
	live := r.streams[key]
	for _, e := range live {
		e.stream.StopHolding()
	}
	r.streams[key] = append(live, &streamEntry{stream: open(len(live) == 0), seen: now})
}

// take returns the stream of key expecting chunk index, or nil.
func (r *streamRegistry) take(key [sha256.Size]byte, index int) *streamEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.streams[key] {
		if e.next == index {
			e.next++
			e.seen = time.Now()
			return e
		}
	}
	return nil
}

// end forgets a stream that has finished.
func (r *streamRegistry) end(key [sha256.Size]byte, done *streamEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	live := r.streams[key][:0]
	for _, e := range r.streams[key] {
		if e != done {
			live = append(live, e)
		}
	}
	if len(live) == 0 {
		delete(r.streams, key)
		return
	}
	r.streams[key] = live
}

// sweep forgets idle streams, at most once a minute; r.mu is held.
func (r *streamRegistry) sweep(now time.Time) {
	if now.Sub(r.lastSweep) < time.Minute {
		return
	}
	r.lastSweep = now
	for key, entries := range r.streams {
		live := entries[:0]
		for _, e := range entries {
			if now.Sub(e.seen) < streamIdleTimeout {
				live = append(live, e)
			}
		}
		if len(live) == 0 {
			delete(r.streams, key)
		} else {
			r.streams[key] = live
		}
	}
}
