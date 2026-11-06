package pkienginereceiver

import (
	"sync"
	"time"
)

type crlCacheEntry struct {
	metrics      crlMetrics
	eTag         string
	lastModified time.Time
}

// Caches processed CRLs across scrape runs.
type crlCacheStore interface {
	Get(key string) (crlCacheEntry, bool)
	Add(key string, value crlCacheEntry)
	// Marks keys as referenced in this scrape and drops the entries that were not
	// referenced in the last crlCacheRetainScrapes scrapes.
	Retain(keys map[string]struct{})
}

// Number of scrapes a CRL is kept after it was last referenced.
// A scrape cut short by errors or a timeout cannot tell an unreferenced CRL from an unreached one,
// and dropping a referenced CRL forces a full download.
const crlCacheRetainScrapes = 3

// Holds the CRLs referenced in the last crlCacheRetainScrapes scrapes.
type mapCRLCache struct {
	mu      sync.Mutex
	entries map[string]crlCacheEntry
	// Scrape generation in which each key was last referenced.
	referenced map[string]uint64
	generation uint64
}

var _ crlCacheStore = (*mapCRLCache)(nil)

func newCrlCache() crlCacheStore {
	return &mapCRLCache{
		entries:    make(map[string]crlCacheEntry),
		referenced: make(map[string]uint64),
	}
}

func (c *mapCRLCache) Get(key string) (crlCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]

	return entry, ok
}

func (c *mapCRLCache) Add(key string, value crlCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = value
}

func (c *mapCRLCache) Retain(keys map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.generation++
	for key := range keys {
		c.referenced[key] = c.generation
	}

	for key := range c.entries {
		if c.generation-c.referenced[key] >= crlCacheRetainScrapes {
			delete(c.entries, key)
		}
	}
	for key, generation := range c.referenced {
		if c.generation-generation >= crlCacheRetainScrapes {
			delete(c.referenced, key)
		}
	}
}

type nopCRLCache struct{}

var _ crlCacheStore = (*nopCRLCache)(nil)

func newNopCrlCache() crlCacheStore {
	return &nopCRLCache{}
}

func (c *nopCRLCache) Get(_ string) (crlCacheEntry, bool) {
	return crlCacheEntry{}, false
}

func (c *nopCRLCache) Add(_ string, _ crlCacheEntry) {}

func (c *nopCRLCache) Retain(_ map[string]struct{}) {}
