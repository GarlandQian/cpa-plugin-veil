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

// streamRegistry tells the chunks of concurrent streams apart. A stream is
// known by its request's ID where the host gives one (CPA v8), else by its
// Caller scope and request body, and by the index of the chunk it expects
// next.
type streamRegistry struct {
	mu        sync.Mutex
	streams   map[[sha256.Size]byte][]*streamEntry
	lastSweep time.Time
}

type streamEntry struct {
	stream *restore.Stream
	next   int
	seen   time.Time
	// finish, where set, is told the stream once it ends or is forgotten.
	finish func(*restore.Stream)
}

// done tells finish the stream is over, once.
func (e *streamEntry) done() {
	if e.finish != nil {
		e.finish(e.stream)
		e.finish = nil
	}
}

func newStreamRegistry() *streamRegistry {
	return &streamRegistry{streams: make(map[[sha256.Size]byte][]*streamEntry)}
}

// start registers a new stream. A key unique to its request belongs to the
// new stream alone; one an earlier stream of it still has is that stream's
// no more. A second stream of the same scope and body while the first is
// live cannot be told apart from it chunk for chunk, so both stop holding
// and are restored line by line.
func (r *streamRegistry) start(key [sha256.Size]byte, unique bool, open func(hold bool) *restore.Stream, finish func(*restore.Stream)) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweep(now)
	live := r.streams[key]
	if unique {
		for _, e := range live {
			e.done()
		}
		live = nil
	}
	for _, e := range live {
		e.stream.StopHolding()
	}
	r.streams[key] = append(live, &streamEntry{stream: open(len(live) == 0), seen: now, finish: finish})
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
	done.done()
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
			} else {
				e.done()
			}
		}
		if len(live) == 0 {
			delete(r.streams, key)
		} else {
			r.streams[key] = live
		}
	}
}

// recordLinks finds the Masking record a response belongs to: the host gives
// no request ID, so a request is known by its Caller scope and the body Veil
// left it with, which the host hands the response interceptors back. It keeps
// two bounded generations.
type recordLinks struct {
	mu   sync.Mutex
	cur  map[[sha256.Size]byte]int64
	prev map[[sha256.Size]byte]int64
}

const recordLinksGenSize = 4096

func newRecordLinks() *recordLinks {
	return &recordLinks{cur: make(map[[sha256.Size]byte]int64)}
}

func (l *recordLinks) put(sum [sha256.Size]byte, key int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.cur) >= recordLinksGenSize {
		l.prev = l.cur
		l.cur = make(map[[sha256.Size]byte]int64, recordLinksGenSize)
	}
	l.cur[sum] = key
}

// take returns and forgets the record of the first of sums it knows.
func (l *recordLinks) take(sums ...[sha256.Size]byte) (int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, sum := range sums {
		for _, gen := range []map[[sha256.Size]byte]int64{l.cur, l.prev} {
			if key, ok := gen[sum]; ok {
				delete(gen, sum)
				return key, true
			}
		}
	}
	return 0, false
}
