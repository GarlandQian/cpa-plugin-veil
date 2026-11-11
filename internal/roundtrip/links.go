package roundtrip

import (
	"crypto/sha256"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
)

// recordLinks correlates a response with its Masking record by the Host's
// request ID, scoped to its caller. A call that names no request has no record
// to find.
type recordLinks struct {
	mu        sync.Mutex
	cur, prev map[[sha256.Size]byte]records.Ref
}

const recordLinksGenSize = 4096

func newRecordLinks() *recordLinks {
	return &recordLinks{cur: make(map[[sha256.Size]byte]records.Ref)}
}

// put links a request to the record a request hook kept of it. A hook that
// kept none leaves the link of an earlier one as it is.
func (l *recordLinks) put(scope, requestID string, ref records.Ref) {
	if requestID == "" || ref.Key == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := requestKey(scope, requestID)
	if _, exists := l.cur[key]; !exists && len(l.cur) >= recordLinksGenSize {
		l.prev = l.cur
		l.cur = make(map[[sha256.Size]byte]records.Ref, recordLinksGenSize)
	}
	delete(l.prev, key)
	l.cur[key] = ref
}

// take consumes a request's link, so that only its first response counts.
func (l *recordLinks) take(scope, requestID string) (records.Ref, bool) {
	if requestID == "" {
		return records.Ref{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := requestKey(scope, requestID)
	ref, ok := l.cur[key]
	if !ok {
		ref, ok = l.prev[key]
	}
	delete(l.cur, key)
	delete(l.prev, key)
	return ref, ok
}
