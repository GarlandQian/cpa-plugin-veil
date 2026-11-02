package detect

import (
	"crypto/sha256"
	"sync"
)

const (
	// cacheMinLen is the shortest text worth caching: below it, hashing costs
	// about as much as detecting.
	cacheMinLen = 256
	// cacheGenSize is how many texts one generation holds. Two generations
	// keep the texts of the last 64k to 128k distinct fields.
	cacheGenSize = 1 << 16
)

// hitCache remembers the hits of long texts. An agent re-sends its whole
// history every turn, so nearly every long text has been seen before. Only
// offsets are kept, never the text. The cache belongs to one Detector, whose
// rules never change, so the text alone is the key.
type hitCache struct {
	mu   sync.Mutex
	cur  map[[sha256.Size]byte][]Hit
	prev map[[sha256.Size]byte][]Hit
}

func newHitCache() *hitCache {
	return &hitCache{cur: make(map[[sha256.Size]byte][]Hit)}
}

// cacheKey hashes text when it is long enough to cache.
func cacheKey(text string) ([sha256.Size]byte, bool) {
	if len(text) < cacheMinLen {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256([]byte(text)), true
}

func (c *hitCache) get(key [sha256.Size]byte) ([]Hit, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hits, ok := c.cur[key]
	if !ok {
		if hits, ok = c.prev[key]; ok {
			c.store(key, hits)
		}
	}
	if !ok {
		return nil, false
	}
	return append([]Hit(nil), hits...), true
}

func (c *hitCache) put(key [sha256.Size]byte, hits []Hit) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store(key, append([]Hit(nil), hits...))
}

// store adds an entry, rolling the generations over when the current one is
// full.
func (c *hitCache) store(key [sha256.Size]byte, hits []Hit) {
	if len(c.cur) >= cacheGenSize {
		c.prev = c.cur
		c.cur = make(map[[sha256.Size]byte][]Hit, cacheGenSize)
	}
	c.cur[key] = hits
}
