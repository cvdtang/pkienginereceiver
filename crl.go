package pkienginereceiver

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.uber.org/zap"
)

var errCrlParseUri = errors.New("failed parsing CDP uri")
var errCrlUnsupportedProtocol = errors.New("unsupported protocol")
var errNotModified = errors.New("CRL not modified")

const (
	httpScheme  = "http"
	httpsScheme = "https"

	cacheReasonNetworkFetch       = "network_fetch"
	cacheReasonFreshInScrape      = "fresh_in_scrape"
	cacheReasonHTTP304NotModified = "http_304_not_modified"
	cacheReasonHTTP304CacheMiss   = "http_304_cache_miss_retry"
)

const (
	crlProcessingStatusFetchFailed int64 = 0
	crlProcessingStatusParseFailed int64 = 1
	crlProcessingStatusSuccess     int64 = 2
)

type fetchResult struct {
	Fetchable    int64
	Data         []byte
	LastModified time.Time
	ETag         string
}

type crlFetchError struct {
	err       error
	retryable bool
}

func (e *crlFetchError) Error() string {
	return e.err.Error()
}

func (e *crlFetchError) Unwrap() error {
	return e.err
}

func newFetchError(err error, retryable bool) error {
	if err == nil {
		return nil
	}

	return &crlFetchError{
		err:       err,
		retryable: retryable,
	}
}

func newRetryableFetchError(err error) error {
	return newFetchError(err, true)
}

func newPermanentFetchError(err error) error {
	return newFetchError(err, false)
}

func isRetryableFetchError(err error) bool {
	var fetchErr *crlFetchError

	return errors.As(err, &fetchErr) && fetchErr.retryable
}

type crlFetcher interface {
	fetch(ctx context.Context, uri string, timeout time.Duration, previousETag string, previousLastModified time.Time) (fetchResult, error)
	fetchHTTP(ctx context.Context, uri string, timeout time.Duration, previousETag string, previousLastModified time.Time) (fetchResult, error)
	fetchLDAP(ctx context.Context, dialer ldapDialer, uri string, timeout time.Duration) (int64, []byte, error)
}

var _ crlFetcher = (*realCrlFetcher)(nil)

type realCrlFetcher struct {
	client *http.Client
}

// Routes CRL fetching to the protocol-specific fetcher.
func (f *realCrlFetcher) fetch(ctx context.Context, uri string, timeout time.Duration, previousETag string, previousLastModified time.Time) (fetchResult, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return fetchResult{}, newPermanentFetchError(fmt.Errorf("%w: %w", errCrlParseUri, err))
	}

	switch u.Scheme {
	case httpScheme, httpsScheme:
		return f.fetchHTTP(ctx, uri, timeout, previousETag, previousLastModified)
	case ldapScheme, ldapsScheme:
		fetchable, data, err := f.fetchLDAP(ctx, &realLdapDialer{}, uri, timeout)

		return fetchResult{
			Fetchable: fetchable,
			Data:      data,
		}, err
	default:
		return fetchResult{}, newPermanentFetchError(fmt.Errorf("%w: %s", errCrlUnsupportedProtocol, u.Scheme))
	}
}

type crlMetrics struct {
	ts                  pcommon.Timestamp
	issuerCommonName    string
	processingStatus    int64
	thisUpdateMinutes   int64
	nextUpdateMinutes   int64
	revokedCertificates int64
	err                 error
}

type crlCacheEntry struct {
	metrics      crlMetrics
	eTag         string
	lastModified time.Time
	lastChecked  time.Time
}

// Initializes CRL metrics with the current timestamp.
func newCrlMetrics() crlMetrics {
	return crlMetrics{
		ts:               pcommon.NewTimestampFromTime(time.Now()),
		processingStatus: crlProcessingStatusFetchFailed,
	}
}

type crl struct {
	logger *zap.Logger
	shared *scrapeShared

	uri     string
	role    metadata.AttributeCrlRole
	kind    metadata.AttributeCrlKind
	fetcher crlFetcher
}

type crlCollectOutcome struct {
	metrics     crlMetrics
	cached      bool
	cacheReason string
}

// Creates a CRL processor for a single issuer CRL URI.
func newCRL(
	logger *zap.Logger,
	shared *scrapeShared,
	uri string,
	role metadata.AttributeCrlRole,
	kind metadata.AttributeCrlKind,
) *crl {
	return &crl{
		logger: logger.With(zap.String("crl.uri", uri)),
		shared: shared,
		uri:    uri,
		role:   role,
		kind:   kind,
		fetcher: &realCrlFetcher{
			client: http.DefaultClient,
		},
	}
}

// Fetches, parses and caches CRL data.
func (c *crl) collect(ctx context.Context) (crlMetrics, error) {
	scheme, unsupported := c.resolveScheme()
	if unsupported {
		return crlMetrics{}, nil
	}
	cacheKey := c.uri

	outcome := crlCollectOutcome{cacheReason: cacheReasonNetworkFetch}
	var shared bool
	defer func() {
		c.logger.Debug("crl cache status",
			zap.Bool("shared", shared),
			zap.Bool("cached", outcome.cached),
			zap.String("cache_reason", outcome.cacheReason),
		)
	}()

	if entry, ok := c.getFreshCacheEntry(cacheKey); ok {
		outcome = crlCollectOutcome{
			metrics:     entry.metrics,
			cached:      true,
			cacheReason: cacheReasonFreshInScrape,
		}
		c.recordCacheOutcome(outcome.cached)

		return outcome.metrics, nil
	}

	collectedWithSingleflight := false
	result, err, doShared := c.shared.crlFetchSfg.Do(cacheKey, func() (any, error) {
		collectedWithSingleflight = true

		return c.collectWithSingleflight(ctx, scheme, cacheKey)
	})
	shared = doShared

	if err != nil {
		return crlMetrics{}, err
	}

	typedOutcome, ok := result.(crlCollectOutcome)
	if !ok {
		return crlMetrics{}, fmt.Errorf("unexpected singleflight result type %T", result)
	}

	outcome = typedOutcome
	// doShared is also true for the leader when duplicates joined, so only
	// non-leader shared callers are treated as cache hits.
	sharedWaiter := doShared && !collectedWithSingleflight
	c.recordCacheOutcome(outcome.cached || sharedWaiter)

	return outcome.metrics, nil
}

func (c *crl) recordCacheOutcome(cached bool) {
	if cached {
		c.shared.crlCacheHits.Add(1)

		return
	}
	c.shared.crlCacheMisses.Add(1)
}

func (c *crl) collectWithSingleflight(ctx context.Context, scheme string, cacheKey string) (crlCollectOutcome, error) {
	// Double check cache inside singleflight.
	if entry, hit := c.getFreshCacheEntry(cacheKey); hit {
		return crlCollectOutcome{
			metrics:     entry.metrics,
			cached:      true,
			cacheReason: cacheReasonFreshInScrape,
		}, nil
	}

	if ctx.Err() != nil {
		return crlCollectOutcome{}, ctx.Err()
	}

	previousETag, previousLastModified := c.getCachedHTTPValidators(cacheKey, scheme)
	res, fetchErr := c.fetchWithRetries(ctx, previousETag, previousLastModified)
	if errors.Is(fetchErr, errNotModified) {
		if metrics, hit := c.refreshCacheEntryAfterNotModified(cacheKey, time.Now(), res); hit {
			return crlCollectOutcome{
				metrics:     metrics,
				cached:      true,
				cacheReason: cacheReasonHTTP304NotModified,
			}, nil
		}

		// A local cache eviction can race with a valid 304 response.
		// Retry once without validators to recover a fresh payload.
		res, fetchErr = c.fetchWithRetries(ctx, "", time.Time{})
		if fetchErr != nil {
			c.logger.Error("crl fetch failed", zap.Error(fetchErr))

			return crlCollectOutcome{
				metrics:     c.cacheFetchError(cacheKey, time.Now(), fetchErr),
				cacheReason: cacheReasonHTTP304CacheMiss,
			}, nil
		}

		return crlCollectOutcome{
			metrics:     c.cacheFetchSuccess(cacheKey, time.Now(), res),
			cacheReason: cacheReasonHTTP304CacheMiss,
		}, nil
	}

	if fetchErr != nil {
		c.logger.Error("crl fetch failed", zap.Error(fetchErr))

		return crlCollectOutcome{
			metrics:     c.cacheFetchError(cacheKey, time.Now(), fetchErr),
			cacheReason: cacheReasonNetworkFetch,
		}, nil
	}

	return crlCollectOutcome{
		metrics:     c.cacheFetchSuccess(cacheKey, time.Now(), res),
		cacheReason: cacheReasonNetworkFetch,
	}, nil
}

// Fetches CRL data with protocol-agnostic retry behavior.
func (c *crl) fetchWithRetries(ctx context.Context, previousETag string, previousLastModified time.Time) (fetchResult, error) {
	maxAttempts := c.shared.cfg.Crl.Retries + 1

	for attempt := range maxAttempts {
		if ctx.Err() != nil {
			return fetchResult{}, ctx.Err()
		}

		res, err := c.fetcher.fetch(ctx, c.uri, c.shared.cfg.Crl.Timeout, previousETag, previousLastModified)
		if err == nil || errors.Is(err, errNotModified) {
			return res, err
		}

		lastAttempt := attempt == maxAttempts-1
		if lastAttempt || !shouldRetryFetchError(err) {
			return res, err
		}

		if c.shared.cfg.Crl.RetryInterval > 0 {
			c.logger.Debug("crl fetch retrying",
				zap.Int("attempt", attempt+1),
				zap.Int("max_attempts", maxAttempts),
				zap.Duration("retry_interval", c.shared.cfg.Crl.RetryInterval),
				zap.Error(err),
			)

			timer := time.NewTimer(c.shared.cfg.Crl.RetryInterval)
			select {
			case <-ctx.Done():
				timer.Stop()

				return fetchResult{}, ctx.Err()
			case <-timer.C:
			}
		}
	}

	return fetchResult{}, fmt.Errorf("unexpected retry loop state")
}

func shouldRetryFetchError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	return isRetryableFetchError(err)
}

// Extracts and validates the CRL URI scheme.
func (c *crl) resolveScheme() (string, bool) {
	u, err := url.Parse(c.uri)
	if err != nil {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	if !isSupportedCrlScheme(scheme) {
		c.logger.Debug("unimplemented CDP protocol", zap.String("scheme", u.Scheme))

		return scheme, true
	}

	return scheme, false
}

// Returns a cache entry when it is fresh (collected or revalidated) for this scrape.
func (c *crl) getFreshCacheEntry(cacheKey string) (crlCacheEntry, bool) {
	entry, ok := c.shared.crlCache.Get(cacheKey)
	if !ok || !entry.isFreshFor(c.shared.scrapeStartTime) {
		return crlCacheEntry{}, false
	}

	return entry, true
}

func (c *crl) getCachedHTTPValidators(cacheKey, scheme string) (string, time.Time) {
	if !isHttpCrlScheme(scheme) {
		return "", time.Time{}
	}

	entry, ok := c.shared.crlCache.Get(cacheKey)
	if !ok {
		return "", time.Time{}
	}

	return entry.eTag, entry.lastModified
}

// Updates cache metadata after an HTTP 304 response.
func (c *crl) refreshCacheEntryAfterNotModified(cacheKey string, now time.Time, res fetchResult) (crlMetrics, bool) {
	entry, ok := c.shared.crlCache.Get(cacheKey)
	if !ok {
		return crlMetrics{}, false
	}

	entry.lastChecked = now
	entry.metrics.ts = pcommon.NewTimestampFromTime(now)
	if res.ETag != "" {
		entry.eTag = res.ETag
	}
	if !res.LastModified.IsZero() {
		entry.lastModified = res.LastModified
	}
	c.shared.crlCache.Add(cacheKey, entry)

	return entry.metrics, true
}

// Stores fetch error metrics in cache.
func (c *crl) cacheFetchError(cacheKey string, now time.Time, fetchErr error) crlMetrics {
	metrics := newCrlMetrics()
	metrics.err = fetchErr
	c.shared.crlCache.Add(cacheKey, crlCacheEntry{
		metrics:     metrics,
		lastChecked: now,
	})

	return metrics
}

// Stores successful fetch metrics and validators in cache.
func (c *crl) cacheFetchSuccess(cacheKey string, now time.Time, res fetchResult) crlMetrics {
	metrics, parseErr := c.createMetrics(res)
	if parseErr != nil {
		metrics.err = parseErr
	}

	c.shared.crlCache.Add(cacheKey, crlCacheEntry{
		metrics:      metrics,
		eTag:         res.ETag,
		lastModified: res.LastModified,
		lastChecked:  now,
	})

	return metrics
}

// Reports whether the CRL scheme is supported.
func isSupportedCrlScheme(scheme string) bool {
	return isHttpCrlScheme(scheme) || isLdapCrlScheme(scheme)
}

// Reports whether the CRL scheme is HTTP(S).
func isHttpCrlScheme(scheme string) bool {
	return scheme == httpScheme || scheme == httpsScheme
}

// Reports whether the CRL scheme is LDAP(S).
func isLdapCrlScheme(scheme string) bool {
	return scheme == ldapScheme || scheme == ldapsScheme
}

// Reports whether a cache entry is fresh for the current scrape start.
func (e crlCacheEntry) isFreshFor(scrapeStart time.Time) bool {
	return !e.lastChecked.Before(scrapeStart)
}

// Parses fetched CRL data and maps it to metric values.
func (c *crl) createMetrics(res fetchResult) (crlMetrics, error) {
	metrics := newCrlMetrics()
	if res.Fetchable == 0 {
		return metrics, nil
	}

	crl, err := c.parse(res.Data)
	if err != nil {
		metrics.processingStatus = crlProcessingStatusParseFailed

		return metrics, err
	}

	metrics.processingStatus = crlProcessingStatusSuccess
	metrics.issuerCommonName = crl.Issuer.CommonName
	metrics.nextUpdateMinutes = int64(math.Floor(time.Until(crl.NextUpdate).Minutes()))
	metrics.thisUpdateMinutes = int64(math.Floor(time.Until(crl.ThisUpdate).Minutes()))
	metrics.revokedCertificates = int64(len(crl.RevokedCertificateEntries))

	return metrics, nil
}

// Decodes and parses CRL bytes from PEM or DER format.
func (c *crl) parse(data []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	return x509.ParseRevocationList(data)
}

// Records CRL metrics to the metrics builder.
func (c *crl) emit(mb *metadata.MetricsBuilder, metrics crlMetrics) {
	mb.RecordPkiengineCrlProcessingStatusDataPoint(
		metrics.ts,
		metrics.processingStatus,
		c.role,
		c.kind,
		c.uri,
	)
	if metrics.processingStatus != crlProcessingStatusSuccess {
		switch metrics.processingStatus {
		case crlProcessingStatusFetchFailed:
			c.logger.Debug("failed fetching CRL, omitting other metrics", zap.Error(metrics.err))
		case crlProcessingStatusParseFailed:
			c.logger.Debug("failed parsing CRL, omitting other metrics", zap.Error(metrics.err))
		default:
			c.logger.Debug(
				"unknown CRL processing status, omitting other metrics",
				zap.Int64("processing_status", metrics.processingStatus),
				zap.Error(metrics.err),
			)
		}

		return
	}

	mb.RecordPkiengineCrlX509ThisUpdateDataPoint(
		metrics.ts,
		metrics.thisUpdateMinutes,
		c.uri,
		c.role,
		c.kind,
		metrics.issuerCommonName,
	)

	mb.RecordPkiengineCrlX509NextUpdateDataPoint(
		metrics.ts,
		metrics.nextUpdateMinutes,
		c.uri,
		c.role,
		c.kind,
		metrics.issuerCommonName,
	)

	mb.RecordPkiengineCrlX509RevokedCertificatesDataPoint(
		metrics.ts,
		metrics.revokedCertificates,
		c.uri,
		c.role,
		c.kind,
		metrics.issuerCommonName,
	)
}
