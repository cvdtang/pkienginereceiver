package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.uber.org/zap"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

// Reported for claimed series whose URI was not collected before the scrape ended.
var errCrlNotCollected = errors.New("CRL not collected before the scrape ended")

// Collects CRLs for one scrape.
//
// Each URI is collected at most once per scrape, regardless of how many issuers,
// roles and kinds reference it; further series of a collected URI reuse its result.
// HTTP CRLs are revalidated against the cache shared across scrapes using the ETag and Last-Modified validators,
// a CRL reported unchanged counts as a cache hit and a downloaded CRL as a cache miss.
type crlCollector struct {
	logger  *zap.Logger
	cfg     crlConfig
	cache   crlCacheStore
	fetcher crlFetcher

	mu      sync.Mutex
	claimed map[string]struct{}
	// Claimed series per URI.
	series  map[string][]crlTask
	results map[string]crlResult

	cacheHits   atomic.Int64
	cacheMisses atomic.Int64
}

// Collected metrics of a URI.
type crlResult struct {
	logger  *zap.Logger
	metrics crlMetrics
}

func newCRLCollector(logger *zap.Logger, cfg crlConfig, cache crlCacheStore, fetcher crlFetcher) *crlCollector {
	return &crlCollector{
		logger:  logger,
		cfg:     cfg,
		cache:   cache,
		fetcher: fetcher,
		claimed: make(map[string]struct{}),
		series:  make(map[string][]crlTask),
		results: make(map[string]crlResult),
	}
}

// Claims the CRL series keyed by uri|role|kind for this scrape.
// Reports whether the series was not claimed before, and whether the caller has to collect its URI.
func (c *crlCollector) claim(task crlTask) (bool, bool) {
	key := strings.Join([]string{task.uri, task.role.String(), task.kind.String()}, "|")

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.claimed[key]; ok {
		return false, false
	}
	c.claimed[key] = struct{}{}

	series, referenced := c.series[task.uri]
	c.series[task.uri] = append(series, task)

	return true, !referenced
}

// Collects the CRL of a URI claimed for collection.
func (c *crlCollector) collect(ctx context.Context, logger *zap.Logger, uri string) (crlMetrics, error) {
	scheme, supported := crlScheme(uri)
	if !supported {
		logger.Debug("unimplemented CDP protocol", zap.String("scheme", scheme))
		metrics := newCrlMetrics()
		c.store(uri, crlResult{logger: logger, metrics: metrics})

		return metrics, nil
	}

	if err := ctx.Err(); err != nil {
		return crlMetrics{}, err
	}

	metrics, cached := c.fetch(ctx, logger, uri, scheme)
	if cached {
		c.cacheHits.Add(1)
	} else {
		c.cacheMisses.Add(1)
	}
	logger.Debug("crl cache status", zap.Bool("cached", cached))
	c.store(uri, crlResult{logger: logger, metrics: metrics})

	return metrics, nil
}

func (c *crlCollector) store(uri string, result crlResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results[uri] = result
}

// Records the metrics of all claimed series.
func (c *crlCollector) emit(mb *metadata.MetricsBuilder) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for uri, series := range c.series {
		result, ok := c.results[uri]
		if !ok {
			metrics := newCrlMetrics()
			metrics.err = errCrlNotCollected
			result = crlResult{logger: c.logger.With(zap.String("crl.uri", uri)), metrics: metrics}
		}
		for _, task := range series {
			task.emit(mb, result.logger, result.metrics)
		}
	}
}

// Fetches and parses the CRL, revalidating the cached CRL for HTTP URIs.
func (c *crlCollector) fetch(ctx context.Context, logger *zap.Logger, uri string, scheme string) (crlMetrics, bool) {
	entry, hasEntry := c.cache.Get(uri)

	var eTag string
	var lastModified time.Time
	if hasEntry && isHttpCrlScheme(scheme) {
		eTag, lastModified = entry.eTag, entry.lastModified
	}

	res, err := c.fetchWithRetries(ctx, logger, uri, eTag, lastModified)
	now := pcommon.NewTimestampFromTime(time.Now())

	// The entry read before the request is reused, so a concurrent cache eviction cannot lose it.
	if errors.Is(err, errNotModified) && hasEntry {
		entry.metrics.ts = now
		if res.ETag != "" {
			entry.eTag = res.ETag
		}
		if !res.LastModified.IsZero() {
			entry.lastModified = res.LastModified
		}
		c.cache.Add(uri, entry)

		return entry.metrics, true
	}

	if err != nil {
		logger.Error("crl fetch failed", zap.Error(err))

		// The cached CRL and its validators are kept, so the next scrape can revalidate it.
		metrics := newCrlMetrics()
		metrics.err = err

		return metrics, false
	}

	metrics, parseErr := createCRLMetrics(res)
	if parseErr != nil {
		metrics.err = parseErr
	}
	c.cache.Add(uri, crlCacheEntry{
		metrics:      metrics,
		eTag:         res.ETag,
		lastModified: res.LastModified,
	})

	return metrics, false
}

// Fetches CRL data with protocol-agnostic retry behavior.
func (c *crlCollector) fetchWithRetries(ctx context.Context, logger *zap.Logger, uri string, eTag string, lastModified time.Time) (fetchResult, error) {
	maxAttempts := c.cfg.Retries + 1

	for attempt := range maxAttempts {
		if ctx.Err() != nil {
			return fetchResult{}, ctx.Err()
		}

		res, err := c.fetcher.fetch(ctx, uri, c.cfg.Timeout, eTag, lastModified)

		if err == nil || errors.Is(err, errNotModified) {
			return res, err
		}

		lastAttempt := attempt == maxAttempts-1
		if lastAttempt || !shouldRetryFetchError(err) {
			return res, err
		}

		if c.cfg.RetryInterval > 0 {
			logger.Debug("crl fetch retrying",
				zap.Int("attempt", attempt+1),
				zap.Int("max_attempts", maxAttempts),
				zap.Duration("retry_interval", c.cfg.RetryInterval),
				zap.Error(err),
			)

			if !sleepCtx(ctx, c.cfg.RetryInterval) {
				return fetchResult{}, ctx.Err()
			}
		}
	}

	return fetchResult{}, fmt.Errorf("unexpected retry loop state")
}

func shouldRetryFetchError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	return isRetryableFetchError(err)
}

// Marks the CRLs referenced in this scrape and drops cached CRLs that were not referenced recently,
// which bounds the cache by the CRLs referenced by issuers.
func (c *crlCollector) pruneCache() {
	c.mu.Lock()
	referenced := make(map[string]struct{}, len(c.series))
	for uri := range c.series {
		referenced[uri] = struct{}{}
	}
	c.mu.Unlock()

	c.cache.Retain(referenced)
}
