package main

import (
	"crypto/sha256"
	"sync"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
)

// recordLinks correlates a response with its Masking record. CPA v8's request
// ID is authoritative and scoped to its caller. Hosts without an ID use body
// hashes only while there is one possible request; ambiguity loses statistics,
// never assigns them to a newer request.
type recordLinks struct {
	mu         sync.Mutex
	cur, prev  map[[sha256.Size]byte]records.Ref
	legacy     map[[sha256.Size]byte]bodyRecordLink
	legacyFull bool
}

type bodyRecordLink struct {
	ref       records.Ref
	ambiguous bool
}

const recordLinksGenSize = 4096

func newRecordLinks() *recordLinks {
	return &recordLinks{
		cur:    make(map[[sha256.Size]byte]records.Ref),
		legacy: make(map[[sha256.Size]byte]bodyRecordLink),
	}
}

// put takes the scoped hash of the body left by a request hook. An empty Ref
// still reserves an unidentified request's body: its response must not take a
// record from another request. Repeated ID-bearing hooks update the same link.
func (l *recordLinks) put(scope, requestID string, bodyHash [sha256.Size]byte, ref records.Ref) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if requestID != "" {
		if ref.Key == 0 {
			return
		}
		key, _ := requestKey(scope, requestID, nil)
		if _, exists := l.cur[key]; !exists && len(l.cur) >= recordLinksGenSize {
			l.prev = l.cur
			l.cur = make(map[[sha256.Size]byte]records.Ref, recordLinksGenSize)
		}
		delete(l.prev, key)
		l.cur[key] = ref
		return
	}
	if l.legacyFull {
		return
	}
	if _, exists := l.legacy[bodyHash]; exists {
		// Keep the tombstone even after a response: neither response order nor
		// when the last indistinguishable request ends is known on this host.
		l.legacy[bodyHash] = bodyRecordLink{ambiguous: true}
		return
	}
	if len(l.legacy) >= 2*recordLinksGenSize {
		// Evicting a pending body would let its late response take a future link
		// for that body. Stop legacy correlation until the instance ends instead.
		l.legacyFull = true
		l.legacy = nil
		return
	}
	l.legacy[bodyHash] = bodyRecordLink{ref: ref}
}

// take consumes a unique association. A missing request ID lookup must never
// fall back to a body match. Without IDs, distinct matching request bodies or
// an earlier collision are ambiguous and remain so until the instance ends.
func (l *recordLinks) take(scope, requestID string, bodies ...[]byte) (records.Ref, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if requestID != "" {
		key, _ := requestKey(scope, requestID, nil)
		ref, ok := l.cur[key]
		if !ok {
			ref, ok = l.prev[key]
		}
		delete(l.cur, key)
		delete(l.prev, key)
		return ref, ok
	}
	var keys [][sha256.Size]byte
	for _, body := range bodies {
		if len(body) == 0 {
			continue
		}
		key := bodySum(scope, body)
		if _, ok := l.legacy[key]; !ok {
			continue
		}
		duplicate := false
		for _, seen := range keys {
			if seen == key {
				duplicate = true
				break
			}
		}
		if !duplicate {
			keys = append(keys, key)
		}
	}
	if len(keys) == 1 {
		link := l.legacy[keys[0]]
		if !link.ambiguous {
			delete(l.legacy, keys[0])
			return link.ref, link.ref.Key != 0
		}
	}
	for _, key := range keys {
		l.legacy[key] = bodyRecordLink{ambiguous: true}
	}
	return records.Ref{}, false
}

// requestKey binds a host request ID to its Caller scope, falling back to the
// scoped body hash only on hosts without IDs. Streams and records share it.
func requestKey(scope, requestID string, body []byte) (key [sha256.Size]byte, unique bool) {
	if requestID == "" {
		return bodySum(scope, body), false
	}
	h := sha256.New()
	h.Write([]byte("request\x00"))
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(requestID))
	h.Sum(key[:0])
	return key, true
}
