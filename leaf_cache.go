package pkienginereceiver

import "sync"

// Caches stored leaf certificates per mount across scrape runs.
// The certificate behind a stored serial is immutable,
// so only serials that were not listed in a previous scrape have to be read from the secret store.
// Serials that are no longer listed (e.g. removed by tidy) are dropped.
type leafCertCache struct {
	// When disabled, every listed serial is read from the secret store.
	enabled bool

	mu     sync.Mutex
	mounts map[string]map[string]leafCert
}

func newLeafCertCache(enabled bool) *leafCertCache {
	return &leafCertCache{
		enabled: enabled,
		mounts:  make(map[string]map[string]leafCert),
	}
}

// Splits listed serials into cached leafs and serials to read,
// dropping cached leafs of the mount that are no longer listed.
func (c *leafCertCache) lookup(mount string, serials []string) ([]leafCert, []string) {
	if !c.enabled {
		return nil, serials
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	previous := c.mounts[mount]
	current := make(map[string]leafCert, len(serials))
	hits := make([]leafCert, 0, len(previous))
	var misses []string
	for _, serial := range serials {
		if leaf, ok := previous[serial]; ok {
			current[serial] = leaf
			hits = append(hits, leaf)

			continue
		}
		misses = append(misses, serial)
	}
	c.mounts[mount] = current

	return hits, misses
}

// Stores a leaf read from the secret store.
func (c *leafCertCache) add(mount, serial string, leaf leafCert) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if leafs, ok := c.mounts[mount]; ok {
		leafs[serial] = leaf
	}
}

// Drops cached mounts which are not part of the given mounts.
func (c *leafCertCache) retainMounts(mounts []string) {
	keep := make(map[string]struct{}, len(mounts))
	for _, mount := range mounts {
		keep[mount] = struct{}{}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for mount := range c.mounts {
		if _, ok := keep[mount]; !ok {
			delete(c.mounts, mount)
		}
	}
}
