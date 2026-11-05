package pkienginereceiver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

const testCrlURI = "http://localhost:8200/pki/crl"

// Holds the CRL cache shared across scrapes.
type testCRLEnv struct {
	t       *testing.T
	cfg     crlConfig
	cache   crlCacheStore
	fetcher crlFetcher
}

func newTestCRLEnv(t *testing.T, fetcher crlFetcher) *testCRLEnv {
	t.Helper()

	return &testCRLEnv{
		t:       t,
		cfg:     crlConfig{Enabled: true, Timeout: time.Second},
		cache:   newCrlCache(),
		fetcher: fetcher,
	}
}

func newHTTPTestCRLEnv(t *testing.T) *testCRLEnv {
	t.Helper()

	return newTestCRLEnv(t, &realCrlFetcher{client: http.DefaultClient})
}

// Starts a new scrape sharing the cache of previous scrapes.
func (e *testCRLEnv) scrape() *crlCollector {
	return newCRLCollector(zaptest.NewLogger(e.t), e.cfg, e.cache, e.fetcher)
}

// Series a test CRL can be claimed with, in claim order.
var testCRLSeries = []crlTask{
	{role: metadata.AttributeCrlRoleSubject, kind: metadata.AttributeCrlKindBase},
	{role: metadata.AttributeCrlRoleSubject, kind: metadata.AttributeCrlKindDelta},
	{role: metadata.AttributeCrlRoleIssuer, kind: metadata.AttributeCrlKindBase},
	{role: metadata.AttributeCrlRoleIssuer, kind: metadata.AttributeCrlKindDelta},
}

func (e *testCRLEnv) get(collector *crlCollector, uri string) crlMetrics {
	e.t.Helper()

	metrics, err := e.getCtx(e.t.Context(), collector, uri)
	require.NoError(e.t, err)

	return metrics
}

// Claims a new series of the CRL, as another issuer, role or kind referencing it would,
// and returns its metrics. Only the first series of a URI collects it.
func (e *testCRLEnv) getCtx(ctx context.Context, collector *crlCollector, uri string) (crlMetrics, error) {
	e.t.Helper()

	for _, series := range testCRLSeries {
		claimed, collect := collector.claim(crlTask{uri: uri, role: series.role, kind: series.kind})
		if !claimed {
			continue
		}
		if collect {
			return collector.collect(ctx, zaptest.NewLogger(e.t), uri)
		}

		collector.mu.Lock()
		defer collector.mu.Unlock()

		return collector.results[uri].metrics, nil
	}
	e.t.Fatalf("all series of %s are claimed", uri)

	return crlMetrics{}, nil
}

func TestCRLCollectorClaim(t *testing.T) {
	t.Parallel()

	collector := newTestCRLEnv(t, nil).scrape()

	claim := func(role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) [2]bool {
		claimed, collect := collector.claim(crlTask{uri: testCrlURI, role: role, kind: kind})

		return [2]bool{claimed, collect}
	}

	assert.Equal(t, [2]bool{true, true}, claim(metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase), "first series collects the URI")
	assert.Equal(t, [2]bool{false, false}, claim(metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase), "duplicate series")

	// Same URI but different series should be claimable and reuse the collection.
	assert.Equal(t, [2]bool{true, false}, claim(metadata.AttributeCrlRoleIssuer, metadata.AttributeCrlKindBase))
	assert.Equal(t, [2]bool{true, false}, claim(metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindDelta))
}

func TestCRLCollectorFetchErrorsAreNotCached(t *testing.T) {
	t.Parallel()

	mockCrlFetcher := newMockcrlFetcher(t)
	env := newTestCRLEnv(t, mockCrlFetcher)
	ctx := t.Context()
	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, "", time.Time{}).Return(fetchResult{}, errors.New("fail")).Once()

	freshMetrics := env.get(env.scrape(), testCrlURI)
	require.Error(t, freshMetrics.err)

	_, ok := env.cache.Get(testCrlURI)
	assert.False(t, ok, "error results should not be cached across scrapes")
}

// Ensures a failed fetch keeps the cached CRL, so the next scrape revalidates it instead of downloading it.
func TestCRLCollectorFetchErrorKeepsValidators(t *testing.T) {
	t.Parallel()

	mockCrlFetcher := newMockcrlFetcher(t)
	env := newTestCRLEnv(t, mockCrlFetcher)
	ctx := t.Context()
	lastModified := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	cached := newCrlMetrics()
	cached.processingStatus = crlProcessingStatusSuccess
	env.cache.Add(testCrlURI, crlCacheEntry{metrics: cached, eTag: `"v1"`, lastModified: lastModified})

	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, `"v1"`, lastModified).Return(fetchResult{}, errors.New("fail")).Once()
	failed := env.get(env.scrape(), testCrlURI)
	require.Error(t, failed.err)
	assert.Equal(t, crlProcessingStatusFetchFailed, failed.processingStatus)

	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, `"v1"`, lastModified).Return(fetchResult{Fetchable: 1}, errNotModified).Once()
	second := env.scrape()
	revalidated := env.get(second, testCrlURI)
	assert.Equal(t, crlProcessingStatusSuccess, revalidated.processingStatus, "the 304 should serve the CRL cached before the failure")
	assert.EqualValues(t, 1, second.cacheHits.Load())
}

func TestCRLCollectorProcessingStatus(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	startTime := time.Now()

	tests := []struct {
		name                 string
		fetchReturnFetchable int64
		fetchReturnData      []byte
		fetchReturnErr       error
		expectMetricsErr     bool
		wantProcessingStatus int64
	}{
		{
			name:                 "Happy Path",
			fetchReturnFetchable: 1,
			fetchReturnData:      data,
			wantProcessingStatus: crlProcessingStatusSuccess,
		},
		{
			name:                 "Fetch Failed",
			fetchReturnErr:       errors.New("fail"),
			expectMetricsErr:     true,
			wantProcessingStatus: crlProcessingStatusFetchFailed,
		},
		{
			name:                 "Parse Failed",
			fetchReturnFetchable: 1,
			fetchReturnData:      []byte("junk"),
			expectMetricsErr:     true,
			wantProcessingStatus: crlProcessingStatusParseFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockCrlFetcher := newMockcrlFetcher(t)
			env := newTestCRLEnv(t, mockCrlFetcher)
			mockCrlFetcher.On("fetch", t.Context(), testCrlURI, time.Second, "", time.Time{}).Return(
				fetchResult{Fetchable: tt.fetchReturnFetchable, Data: tt.fetchReturnData},
				tt.fetchReturnErr,
			)

			metrics := env.get(env.scrape(), testCrlURI)

			if tt.expectMetricsErr {
				require.Error(t, metrics.err)
			} else {
				require.NoError(t, metrics.err)
			}
			assert.GreaterOrEqual(t, metrics.ts.AsTime(), startTime)
			assert.Equal(t, tt.wantProcessingStatus, metrics.processingStatus)
		})
	}
}

func TestCRLCollectorUnsupportedSchemeSkipsFetch(t *testing.T) {
	t.Parallel()

	env := newTestCRLEnv(t, newMockcrlFetcher(t))
	collector := env.scrape()

	before := time.Now()
	metrics := env.get(collector, "ftp://example.com/crl")
	assert.Equal(t, crlProcessingStatusFetchFailed, metrics.processingStatus)
	assert.False(t, metrics.ts.AsTime().Before(before.Truncate(time.Microsecond)), "the status should be timestamped at collection, not the zero time")
	assert.EqualValues(t, 0, collector.cacheHits.Load()+collector.cacheMisses.Load())
}

func TestCRLCollectorRetrySuccessOnRetryableError(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	mockCrlFetcher := newMockcrlFetcher(t)
	env := newTestCRLEnv(t, mockCrlFetcher)
	env.cfg.Retries = 1
	ctx := t.Context()

	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, "", time.Time{}).Return(
		fetchResult{},
		newRetryableFetchError(errors.New("temporary failure")),
	).Once()
	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, "", time.Time{}).Return(
		fetchResult{Fetchable: 1, Data: data},
		nil,
	).Once()

	metrics := env.get(env.scrape(), testCrlURI)
	require.NoError(t, metrics.err)
	assert.Equal(t, crlProcessingStatusSuccess, metrics.processingStatus)
}

func TestCRLCollectorNoRetryOnPermanentError(t *testing.T) {
	t.Parallel()

	mockCrlFetcher := newMockcrlFetcher(t)
	env := newTestCRLEnv(t, mockCrlFetcher)
	env.cfg.Retries = 3

	mockCrlFetcher.On("fetch", t.Context(), testCrlURI, time.Second, "", time.Time{}).Return(
		fetchResult{},
		newPermanentFetchError(errors.New("invalid request")),
	).Once()

	metrics := env.get(env.scrape(), testCrlURI)
	assert.Equal(t, crlProcessingStatusFetchFailed, metrics.processingStatus)
	assert.ErrorContains(t, metrics.err, "invalid request")
}

func TestCRLCollectorRetryIntervalHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	mockCrlFetcher := newMockcrlFetcher(t)
	env := newTestCRLEnv(t, mockCrlFetcher)
	env.cfg.Retries = 1
	env.cfg.RetryInterval = time.Second

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()

	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, "", time.Time{}).Return(
		fetchResult{},
		newRetryableFetchError(errors.New("transient error")),
	).Once()

	start := time.Now()
	metrics, err := env.getCtx(ctx, env.scrape(), testCrlURI)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, crlProcessingStatusFetchFailed, metrics.processingStatus)
	require.ErrorIs(t, metrics.err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 250*time.Millisecond, "retry wait should stop early on context cancellation")
}

func TestCRLCollectorFetchesOncePerScrape(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	_, data := createTestCrlData(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpRequestCount.Add(1)
		// Simulate latency to ensure overlap.
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	env := newHTTPTestCRLEnv(t)
	collector := env.scrape()

	// Concurrent issuers claiming every series of the URI, twice.
	var collects atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		for _, series := range testCRLSeries {
			wg.Go(func() {
				if _, collect := collector.claim(crlTask{uri: server.URL, role: series.role, kind: series.kind}); !collect {
					return
				}
				collects.Add(1)
				_, err := collector.collect(t.Context(), zaptest.NewLogger(t), server.URL)
				assert.NoError(t, err)
			})
		}
	}
	wg.Wait()

	assert.EqualValues(t, 1, collects.Load(), "exactly one claim should collect the URI")
	assert.Equal(t, int32(1), httpRequestCount.Load(), "expected exactly 1 HTTP request")
	assert.EqualValues(t, 0, collector.cacheHits.Load(), "series reusing the collection are not cache hits")
	assert.EqualValues(t, 1, collector.cacheMisses.Load(), "only the network fetch should count as a cache miss")
}

// Ensures HTTP CRL URIs are checked once per scrape and revalidated next scrape.
func TestCRLCollectorHTTPCaching(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	etag := `"fake-etag"`
	_, data := createTestCrlData(t)
	requestHasValidator := atomic.Bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestCount.Add(1)

		if r.Header.Get("If-None-Match") == etag {
			requestHasValidator.Store(true)
			w.WriteHeader(http.StatusNotModified)

			return
		}

		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	env := newHTTPTestCRLEnv(t)

	first := env.scrape()
	env.get(first, server.URL)
	env.get(first, server.URL)
	assert.Equal(t, int32(1), httpRequestCount.Load(), "same scrape should not trigger a second network check")
	assert.EqualValues(t, 0, first.cacheHits.Load())
	assert.EqualValues(t, 1, first.cacheMisses.Load())

	second := env.scrape()
	metrics := env.get(second, server.URL)
	assert.Equal(t, int32(2), httpRequestCount.Load(), "new scrape should trigger one HTTP revalidation")
	assert.True(t, requestHasValidator.Load(), "revalidation must send If-None-Match")
	assert.Equal(t, crlProcessingStatusSuccess, metrics.processingStatus)
	assert.EqualValues(t, 1, second.cacheHits.Load(), "304 revalidation should count as a cache hit")
	assert.EqualValues(t, 0, second.cacheMisses.Load())
}

// Ensures a 304 revalidation reuses the absolute validity window of the cached CRL.
func TestCRLCollectorHTTP304PreservesAbsoluteValidityWindow(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	env := newHTTPTestCRLEnv(t)
	seeded := newCrlMetrics()
	seeded.thisUpdate = time.Now().Add(-30 * time.Minute)
	seeded.nextUpdate = time.Now().Add(90 * time.Minute)
	env.cache.Add(server.URL, crlCacheEntry{metrics: seeded, eTag: `"fake-etag"`})

	metrics := env.get(env.scrape(), server.URL)
	assert.Equal(t, seeded.thisUpdate, metrics.thisUpdate, "304 must preserve the absolute thisUpdate")
	assert.Equal(t, seeded.nextUpdate, metrics.nextUpdate, "304 must preserve the absolute nextUpdate")
}

// Ensures a cache eviction during revalidation does not lose the CRL answered with 304.
func TestCRLCollectorHTTP304SurvivesConcurrentEviction(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	etag := `"v1"`
	var fullRequestCount atomic.Int32
	env := newHTTPTestCRLEnv(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			for range crlCacheRetainScrapes {
				env.cache.Retain(map[string]struct{}{})
			}
			w.WriteHeader(http.StatusNotModified)

			return
		}

		fullRequestCount.Add(1)
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	env.get(env.scrape(), server.URL)

	second := env.scrape()
	metrics := env.get(second, server.URL)
	assert.Equal(t, crlProcessingStatusSuccess, metrics.processingStatus)
	assert.Equal(t, int32(1), fullRequestCount.Load(), "the 304 should be served from the entry read before the request")
	assert.EqualValues(t, 1, second.cacheHits.Load())
	_, ok := env.cache.Get(server.URL)
	assert.True(t, ok, "the revalidated entry should be cached again")
}

// Ensures HTTP CRLs are downloaded every scrape without conditional headers when the cache is disabled.
func TestCRLCollectorHTTPCachingDisabled(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	_, data := createTestCrlData(t)
	conditionalHeaderSeen := atomic.Bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestCount.Add(1)
		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			conditionalHeaderSeen.Store(true)
		}

		w.Header().Set("ETag", `"fake-etag"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	env := newHTTPTestCRLEnv(t)
	env.cache = newNopCrlCache()

	env.get(env.scrape(), server.URL)
	env.get(env.scrape(), server.URL)
	assert.Equal(t, int32(2), httpRequestCount.Load(), "new scrape should fetch again when cache is disabled")
	assert.False(t, conditionalHeaderSeen.Load(), "disabled cache must not send conditional headers")
}

// Ensures LDAP CRLs are downloaded every scrape, as LDAP offers no revalidation.
func TestCRLCollectorLdapCaching(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	uri := "ldap://example.com/cn=test?certificateRevocationList"

	mockCrlFetcher := newMockcrlFetcher(t)
	env := newTestCRLEnv(t, mockCrlFetcher)
	mockCrlFetcher.On("fetch", t.Context(), uri, time.Second, "", time.Time{}).Return(
		fetchResult{Fetchable: 1, Data: data},
		nil,
	).Twice()

	env.get(env.scrape(), uri)
	env.get(env.scrape(), uri)
}

// Ensures validators from 304 responses are persisted for subsequent revalidation.
func TestCRLCollectorHTTP304UpdatesValidators(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	ctx := t.Context()

	initialFallbackDate := time.Date(2025, 1, 8, 1, 0, 0, 0, time.UTC)
	upgradedLastModified := time.Date(2025, 1, 9, 1, 0, 0, 0, time.UTC)
	upgradedETag := `"v2"`

	mockCrlFetcher := newMockcrlFetcher(t)
	env := newTestCRLEnv(t, mockCrlFetcher)
	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, "", time.Time{}).Return(
		fetchResult{Fetchable: 1, Data: data, LastModified: initialFallbackDate},
		nil,
	).Once()
	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, "", initialFallbackDate).Return(
		fetchResult{Fetchable: 1, ETag: upgradedETag, LastModified: upgradedLastModified},
		errNotModified,
	).Once()
	mockCrlFetcher.On("fetch", ctx, testCrlURI, time.Second, upgradedETag, upgradedLastModified).Return(
		fetchResult{Fetchable: 1, ETag: upgradedETag, LastModified: upgradedLastModified},
		errNotModified,
	).Once()

	for range 3 {
		env.get(env.scrape(), testCrlURI)
	}
}

// Ensures the cache keeps unreferenced CRLs for crlCacheRetainScrapes scrapes,
// as a scrape cut short cannot tell an unreferenced CRL from an unreached one.
func TestCRLCollectorPruneCache(t *testing.T) {
	t.Parallel()

	_, data := createTestCrlData(t)
	var fullRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)

			return
		}
		fullRequests.Add(1)
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	env := newHTTPTestCRLEnv(t)
	scrape := func(paths ...string) {
		collector := env.scrape()
		for _, path := range paths {
			env.get(collector, server.URL+path)
		}
		collector.pruneCache()
	}

	scrape("/a", "/b")
	for range crlCacheRetainScrapes - 1 {
		scrape("/a")
	}
	_, ok := env.cache.Get(server.URL + "/b")
	assert.True(t, ok, "recently referenced CRL should stay cached")

	// Referencing /b again revalidates it instead of downloading it.
	scrape("/a", "/b")
	assert.EqualValues(t, 2, fullRequests.Load(), "only the first scrape should download")

	for range crlCacheRetainScrapes {
		scrape("/a")
	}
	_, ok = env.cache.Get(server.URL + "/a")
	assert.True(t, ok, "referenced CRL should stay cached")
	_, ok = env.cache.Get(server.URL + "/b")
	assert.False(t, ok, "CRL no longer referenced should be dropped")
}

// Ensures keys referenced without a cache entry, e.g. failed fetches, do not accumulate.
func TestCRLCacheRetainDropsStaleReferences(t *testing.T) {
	t.Parallel()

	cache := newCrlCache().(*mapCRLCache)
	cache.Retain(map[string]struct{}{"failed": {}})
	for range crlCacheRetainScrapes {
		cache.Retain(map[string]struct{}{})
	}

	assert.Empty(t, cache.referenced)
	assert.Empty(t, cache.entries)
}

// Ensures a series claimed but not collected, as the scrape ended first,
// is reported as failed to fetch instead of being omitted.
func TestCRLCollectorEmitsUncollectedSeries(t *testing.T) {
	t.Parallel()

	run := createTestScrapeState(t)
	task := crlTask{uri: testCrlURI, role: metadata.AttributeCrlRoleSubject, kind: metadata.AttributeCrlKindBase}
	claimed, collect := run.crls.claim(task)
	require.True(t, claimed)
	require.True(t, collect)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := run.crls.collect(ctx, zaptest.NewLogger(t), testCrlURI)
	require.ErrorIs(t, err, context.Canceled)

	run.crls.emit(run.mb)
	md := run.mb.Emit()

	require.Equal(t, 1, md.ResourceMetrics().Len())
	metrics := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 1, metrics.Len(), "only the processing status should be reported")
	assert.Equal(t, "pkiengine.crl.processing_status", metrics.At(0).Name())
	require.Equal(t, 1, metrics.At(0).Gauge().DataPoints().Len())
	dp := metrics.At(0).Gauge().DataPoints().At(0)
	assert.Equal(t, crlProcessingStatusFetchFailed, dp.IntValue())
	assert.Equal(t, testCrlURI, requireAttr(t, dp.Attributes(), "crl.uri").Str())
}
