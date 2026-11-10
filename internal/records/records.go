// Package records keeps the Masking records: what Veil did in each Round trip
// whose request had a Hit or was a Stopped request, told without the values
// themselves (ADR-0005). The latest records are in memory, the newest of them
// with the text around each value as the upstream got it; with a persistent
// directory they also go to disk, a file a day, without that text.
package records

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// keepRecords is how many records memory holds, and keepSnips how many of
	// the newest of them keep their Snips.
	keepRecords = 1000
	keepSnips   = 400
	// queueLen is how many records may wait to be kept; one more is dropped
	// rather than make a request wait.
	queueLen = 256
)

// Value is one value a request had, as Veil sent it or would have.
type Value struct {
	Placeholder string   `json:"p"`
	Kind        string   `json:"kind"`
	Rule        string   `json:"rule,omitempty"`
	Head        string   `json:"head,omitempty"` // a key's prefix or the first character
	Len         int      `json:"len"`            // in characters
	N           int      `json:"n"`              // the places the request had it
	Action      string   `json:"action"`         // mask, warn or block
	Paths       []string `json:"paths,omitempty"`
	New         bool     `json:"new,omitempty"` // no earlier request of the caller had it
}

// Stopped says why a request did not reach the upstream.
const (
	StoppedBlock     = "block"     // a value's Kind has the block Action
	StoppedMalformed = "malformed" // the body starts like JSON and does not parse
	StoppedError     = "error"     // masking failed
)

// Record is one Round trip's masking.
type Record struct {
	Key     int64     `json:"key"` // unique, a later record's larger
	Time    time.Time `json:"time"`
	Caller  string    `json:"caller,omitempty"` // the Caller scope; "" the Default scope
	Model   string    `json:"model,omitempty"`
	Format  string    `json:"format,omitempty"` // the request's source format
	N       int       `json:"n"`                // places masked, warned about or blocked
	Values  []Value   `json:"values,omitempty"`
	Stopped string    `json:"stopped,omitempty"`
	Took    int64     `json:"took"` // microseconds masking took
	// Snips are, by Placeholder, the text around its first place; in memory
	// only, for the newest records.
	Snips map[string]string `json:"snips,omitempty"`
	// Restored is what the response put back, once it is done.
	Restored *Restored `json:"restored,omitempty"`
	// Patch marks a line on disk that adds to the record of its Key written
	// before it: Restored, or what a later Pass of the request found, which is
	// more Values with their N, its Took, and Stopped if it stopped the
	// request.
	Patch bool `json:"patch,omitempty"`
}

// patched returns r with what a patch says added to it.
func (r Record) patched(patch Record) Record {
	if patch.Restored != nil {
		r.Restored = r.Restored.merge(*patch.Restored)
	}
	if len(patch.Values) > 0 || patch.Stopped != "" || patch.Took != 0 {
		r = r.extend(patch)
	}
	return r
}

// extend returns r with what a later Pass found added: more's Values, which
// r does not have, and their Snips. A record already handed out keeps what it
// had.
func (r Record) extend(more Record) Record {
	r.N += more.N
	r.Took += more.Took
	r.Values = append(r.Values[:len(r.Values):len(r.Values)], more.Values...)
	if more.Stopped != "" {
		r.Stopped = more.Stopped
	}
	if len(more.Snips) > 0 {
		snips := make(map[string]string, len(r.Snips)+len(more.Snips))
		for _, from := range []map[string]string{r.Snips, more.Snips} {
			for placeholder, snip := range from {
				snips[placeholder] = snip
			}
		}
		r.Snips = snips
	}
	return r
}

// Restored is what the responses to a request put back.
type Restored struct {
	// Back are, by Placeholder or Stand-in, the places restored.
	Back map[string]int `json:"back,omitempty"`
	// Unrestored are the Placeholders the responses had that the Vault did
	// not hold, such as ones from provider-held history after a restart.
	Unrestored map[string]int `json:"unrestored,omitempty"`
	Time       time.Time      `json:"time"`
}

// merge returns a new Restored with o's counts added to r's, so a record
// already handed out keeps what it had.
func (r *Restored) merge(o Restored) *Restored {
	out := &Restored{Back: map[string]int{}, Unrestored: map[string]int{}, Time: o.Time}
	for _, from := range []*Restored{r, &o} {
		if from == nil {
			continue
		}
		for p, n := range from.Back {
			out.Back[p] += n
		}
		for p, n := range from.Unrestored {
			out.Unrestored[p] += n
		}
	}
	if len(out.Back) == 0 {
		out.Back = nil
	}
	if len(out.Unrestored) == 0 {
		out.Unrestored = nil
	}
	return out
}

// Ref follows an accepted record across directory changes. It belongs to the
// Store that returned it; only Key is part of the public record format.
type Ref struct {
	Key   int64
	at    time.Time
	dir   string
	owner *Store
}

// Store keeps records. Submission never holds the lock used for disk I/O.
// The writer orders records, restore counts, directory changes and clears.
type Store struct {
	queue    chan item
	finished chan struct{}
	dropped  atomic.Int64
	last     atomic.Int64
	clock    func() time.Time

	control  sync.Mutex // at most one control item awaiting the writer
	intake   sync.Mutex
	closed   bool
	draining bool
	target   string
	// Only cleared directories need a watermark, not every record or directory
	// ever seen. This also invalidates old refs when a directory is revisited.
	cleared map[string]int64

	mu       sync.Mutex
	dir      string
	ring     []Record
	disk     diskState
	revision uint64
}

type item struct {
	rec      Record
	ref      Ref
	restored *Restored
	more     bool         // rec adds to the record ref follows
	control  func() error // runs under mu, after all preceding records
	done     chan error
}

// New returns a Store keeping records in memory only, until SetDir. Close
// must be called before its owner releases the plugin or its directory.
func New() *Store {
	// One reserved slot lets a control operation enter even with a full data
	// queue, without making requests wait for disk I/O.
	s := &Store{queue: make(chan item, queueLen+1), finished: make(chan struct{}), clock: time.Now, cleared: make(map[string]int64)}
	go s.run()
	return s
}

// SetDir finishes previously accepted records in their old directory, then
// shows only records in dir. Old files stay where they are. A response's Ref
// continues to target the directory where its request was accepted.
func (s *Store) SetDir(dir string) {
	if dir != "" {
		dir = recordsDir(dir)
	}
	_ = s.command(func() {
		s.target = dir
	}, func() error {
		if s.dir != dir {
			s.dir, s.ring, s.disk = dir, nil, diskState{}
			s.revision++
		}
		return nil
	})
}

// Persisted says the current view has a persistent directory.
func (s *Store) Persisted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dir != ""
}

// Dropped counts submissions rejected because the queue was full.
func (s *Store) Dropped() int64 { return s.dropped.Load() }

// Add assigns a Key and accepts r without waiting for the writer. A full
// queue drops and counts r; a closed Store rejects it.
func (s *Store) Add(r Record) (Ref, bool) {
	s.intake.Lock()
	defer s.intake.Unlock()
	if s.closed || s.draining {
		return Ref{}, false
	}
	if r.Time.IsZero() {
		r.Time = s.clock()
	}
	r.Key = s.nextKey(r.Time)
	ref := Ref{Key: r.Key, at: r.Time, dir: s.target, owner: s}
	if !s.enqueue(item{rec: r, ref: ref}) {
		return Ref{}, false
	}
	return ref, true
}

// Restore adds what a response put back to the record ref follows, in the
// Store that returned it. The zero Ref follows none.
func (ref Ref) Restore(back, unrestored map[string]int) {
	if ref.owner != nil {
		ref.owner.Restore(ref, back, unrestored)
	}
}

// Append adds what a later Pass of the request found to the record ref
// follows: more's Values, which the record must not have yet, its N for them,
// its Took, its Snips, and Stopped if the Pass stopped the request. Like Add,
// it drops excess submissions without waiting. The zero Ref follows none.
func (ref Ref) Append(more Record) {
	s := ref.owner
	if s == nil {
		return
	}
	s.intake.Lock()
	defer s.intake.Unlock()
	if s.closed || s.draining || ref.Key <= s.cleared[ref.dir] {
		return
	}
	s.enqueue(item{ref: ref, rec: more, more: true})
}

// Restore follows the original record, even after SetDir. A clear in that
// directory invalidates older refs, including ones held by active streams.
// Like Add, it drops excess submissions without waiting, until BeginDrain.
func (s *Store) Restore(ref Ref, back, unrestored map[string]int) {
	s.intake.Lock()
	defer s.intake.Unlock()
	if s.closed || ref.owner != s || ref.Key <= s.cleared[ref.dir] {
		return
	}
	r := &Restored{Back: back, Unrestored: unrestored, Time: s.clock()}
	it := item{ref: ref, restored: r}
	if s.draining {
		// Only final stream tallies remain after the runtime drains its calls.
		s.queue <- it
	} else {
		s.enqueue(it)
	}
}

// enqueue runs under intake. Leave the reserved slot to command.
func (s *Store) enqueue(it item) bool {
	if len(s.queue) >= cap(s.queue)-1 {
		s.dropped.Add(1)
		return false
	}
	s.queue <- it
	return true
}

// command changes intake at the same point it queues a writer operation.
// Requests may keep enqueueing while the caller waits for the operation.
func (s *Store) command(accept func(), apply func() error) error {
	s.control.Lock()
	defer s.control.Unlock()
	s.intake.Lock()
	if s.closed {
		s.intake.Unlock()
		<-s.finished
		return nil
	}
	if accept != nil {
		accept()
	}
	done := make(chan error, 1)
	s.queue <- item{control: apply, done: done}
	s.intake.Unlock()
	return <-done
}

// Flush waits for everything accepted before it. It is also safe after Close.
func (s *Store) Flush() { _ = s.command(nil, func() error { return nil }) }

// BeginDrain rejects new records and lets final Restore calls wait for queue
// space instead of dropping them. The owner must first stop request calls;
// after finalizing active streams it calls Close to join the writer.
func (s *Store) BeginDrain() {
	s.intake.Lock()
	defer s.intake.Unlock()
	s.draining = true
}

// Close rejects new submissions, drains accepted records and stops the
// writer. Concurrent or repeated closes wait for the same completion.
func (s *Store) Close() {
	s.control.Lock()
	defer s.control.Unlock()
	s.intake.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.intake.Unlock()
	<-s.finished
}

// nextKey is a key larger than any before, near t in microseconds.
func (s *Store) nextKey(t time.Time) int64 {
	for {
		last := s.last.Load()
		key := max(t.UnixMicro(), last+1)
		if s.last.CompareAndSwap(last, key) {
			return key
		}
	}
}

func (s *Store) run() {
	defer close(s.finished)
	for it := range s.queue {
		s.mu.Lock()
		switch {
		case it.control != nil:
			it.done <- it.control()
		case it.restored != nil:
			s.patch(it.ref, Record{Restored: it.restored})
		case it.more:
			s.patch(it.ref, it.rec)
		default:
			s.keep(it.rec)
		}
		s.mu.Unlock()
	}
}

// keep puts r in memory and, with a directory, on disk.
func (s *Store) keep(r Record) {
	s.ring = append(s.ring, r)
	if n := len(s.ring); n > keepSnips {
		s.ring[n-keepSnips-1].Snips = nil
	}
	if len(s.ring) > keepRecords {
		s.ring = append(s.ring[:0:0], s.ring[len(s.ring)-keepRecords:]...)
	}
	if s.dir != "" {
		s.write(r)
	}
}

// patch adds to the record ref follows what its response restored or a later
// Pass found. It runs on the writer. What comes for a record of an old
// directory never enters the current memory view or prunes the files the
// operator left there.
func (s *Store) patch(ref Ref, patch Record) {
	patch.Key, patch.Time, patch.Patch = ref.Key, ref.at, true
	if ref.dir != s.dir {
		if ref.dir != "" {
			appendRecord(ref.dir, patch)
		}
		return
	}
	for i := len(s.ring) - 1; i >= 0; i-- {
		if s.ring[i].Key == ref.Key {
			s.ring[i] = s.ring[i].patched(patch)
			if len(s.ring)-i > keepSnips {
				s.ring[i].Snips = nil
			}
			break
		}
	}
	if s.dir != "" {
		s.write(patch)
	}
}

// Clear removes the current view and its files after all preceding writes.
// New records continue after the cutoff; older restore counts cannot recreate
// a cleared record. Other directories and the Vault are untouched.
func (s *Store) Clear() error {
	return s.command(func() {
		s.cleared[s.target] = s.last.Load()
	}, func() error {
		s.ring = nil
		s.revision++
		return s.clearDisk()
	})
}
