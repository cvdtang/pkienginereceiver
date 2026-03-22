package pkienginereceiver

import lru "github.com/hashicorp/golang-lru/v2"

type crlCacheStore interface {
	Get(key string) (crlCacheEntry, bool)
	Add(key string, value crlCacheEntry)
	Remove(key string)
}

type lruCRLCache struct {
	cache *lru.Cache[string, crlCacheEntry]
}

var _ crlCacheStore = (*lruCRLCache)(nil)

func newLruCrlCache(size int, onEvict func(key string, value crlCacheEntry)) (crlCacheStore, error) {
	var (
		cache *lru.Cache[string, crlCacheEntry]
		err   error
	)

	if onEvict != nil {
		cache, err = lru.NewWithEvict(size, onEvict)
	} else {
		cache, err = lru.New[string, crlCacheEntry](size)
	}
	if err != nil {
		return nil, err
	}

	return &lruCRLCache{cache: cache}, nil
}

func (c *lruCRLCache) Get(key string) (crlCacheEntry, bool) {
	return c.cache.Get(key)
}

func (c *lruCRLCache) Add(key string, value crlCacheEntry) {
	c.cache.Add(key, value)
}

func (c *lruCRLCache) Remove(key string) {
	c.cache.Remove(key)
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

func (c *nopCRLCache) Remove(_ string) {}
