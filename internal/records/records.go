// Package records keeps the Masking records: what Veil did to each request
// that had a Hit or was a Stopped request, told without the values
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

// Record is one request's masking.
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
	// Patch marks a line on disk that adds Restored to the record of its Key
	// written before it.
	Patch bool `json:"patch,omitempty"`
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

// Store keeps records. It is safe for concurrent use.
type Store struct {
	queue   chan item
	dropped atomic.Int64
	last    atomic.Int64
	clock   func() time.Time

	mu   sync.Mutex
	dir  string   // where the days are kept, or "" for memory only
	ring []Record // the newest last
	disk diskState
}

// item is a record to keep, what a response restored, or a flush to answer
// once those before it are.
type item struct {
	rec      Record
	restored *Restored // for the record rec.Key
	done     chan struct{}
}

// New returns a Store keeping records in memory only, until SetDir.
func New() *Store {
	s := &Store{queue: make(chan item, queueLen), clock: time.Now}
	go s.run()
	return s
}

// SetDir keeps the records on disk under dir from now on, or in memory only
// when dir is "".
func (s *Store) SetDir(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dir != "" {
		dir = recordsDir(dir)
	}
	if dir != s.dir {
		s.dir = dir
		s.disk = diskState{}
	}
}

// Persisted says the records go to disk too.
func (s *Store) Persisted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dir != ""
}

// Dropped is how many records were dropped because too many waited.
func (s *Store) Dropped() int64 {
	return s.dropped.Load()
}

// Add hands r to be kept, giving it its Key and, where unset, its Time, and
// returns the Key. It never waits: when too many records wait already, r is
// dropped, counted, and Add returns false.
func (s *Store) Add(r Record) (int64, bool) {
	if r.Time.IsZero() {
		r.Time = s.clock()
	}
	r.Key = s.nextKey(r.Time)
	select {
	case s.queue <- item{rec: r}:
		return r.Key, true
	default:
		s.dropped.Add(1)
		return 0, false
	}
}

// Restore adds what a response restored to the record with key. Like Add, it
// never waits, and drops what does not fit.
func (s *Store) Restore(key int64, back, unrestored map[string]int) {
	r := &Restored{Back: back, Unrestored: unrestored, Time: s.clock()}
	select {
	case s.queue <- item{rec: Record{Key: key}, restored: r}:
	default:
		s.dropped.Add(1)
	}
}

// Flush waits until every record added before it is kept.
func (s *Store) Flush() {
	done := make(chan struct{})
	s.queue <- item{done: done}
	<-done
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
	for it := range s.queue {
		switch {
		case it.done != nil:
			close(it.done)
		case it.restored != nil:
			s.patch(it.rec.Key, *it.restored)
		default:
			s.keep(it.rec)
		}
	}
}

// keep puts r in memory and, with a directory, on disk.
func (s *Store) keep(r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// patch adds what a response restored to the record with key, in memory and
// on disk.
func (s *Store) patch(key int64, r Restored) {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := time.UnixMicro(key)
	for i := len(s.ring) - 1; i >= 0; i-- {
		if s.ring[i].Key == key {
			s.ring[i].Restored = s.ring[i].Restored.merge(r)
			at = s.ring[i].Time
			break
		}
	}
	if s.dir != "" {
		s.write(Record{Key: key, Time: at, Patch: true, Restored: &r})
	}
}

// Clear deletes every record kept, in memory and on disk. The Vault is not
// touched: what is being restored goes on restoring.
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring = nil
	return s.clearDisk()
}
