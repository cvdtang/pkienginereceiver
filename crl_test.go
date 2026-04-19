package pkienginereceiver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func createTestCRL(t *testing.T) (*crl, *scrapeShared) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	uri := "http://localhost:8200/pki/crl"

	state := createTestScrapeState(t)

	role := metadata.AttributeCrlRoleSubject
	kind := metadata.AttributeCrlKindBase

	return newCRL(logger, state, uri, role, kind), state
}

func createHTTPTestCRL(t *testing.T, uri string) (*crl, *scrapeShared) {
	t.Helper()

	crl, state := createTestCRL(t)
	crl.fetcher = &realCrlFetcher{client: http.DefaultClient}
	crl.uri = uri

	return crl, state
}

func advanceScrape(state *scrapeShared) {
	state.scrapeStartTime = state.scrapeStartTime.Add(time.Second)
}

var (
	testCrlDataOnce sync.Once
	testCrlDER      []byte
	testCrlPEM      []byte
	testCrlDataErr  error
)

// Helper to generate a real, cryptographically valid CRL
// and return it in both DER and PEM formats.
func createTestCrlData(t *testing.T) ([]byte, []byte) {
	t.Helper()

	testCrlDataOnce.Do(func() {
		// Generate a CA private key.
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			testCrlDataErr = err

			return
		}

		// Create a dummy CA certificate template.
		caTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "Test CA",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		// Create the CA certificate.
		caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if err != nil {
			testCrlDataErr = err

			return
		}
		caCert, err := x509.ParseCertificate(caCertDER)
		if err != nil {
			testCrlDataErr = err

			return
		}

		// Create the revocation list template.
		crlTemplate := &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(3 * 24 * time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{
					SerialNumber:   big.NewInt(2),
					RevocationTime: time.Now(),
				},
			},
		}

		// Sign the CRL with the CA key.
		testCrlDER, testCrlDataErr = x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
		if testCrlDataErr != nil {
			return
		}

		// Encode to PEM.
		testCrlPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "X509 CRL",
			Bytes: testCrlDER,
		})
	})

	require.NoError(t, testCrlDataErr)
	require.NotEmpty(t, testCrlDER)
	require.NotEmpty(t, testCrlPEM)

	return append([]byte(nil), testCrlDER...), append([]byte(nil), testCrlPEM...)
}

func TestCRL_Collect(t *testing.T) {
	t.Parallel()

	crl, state := createTestCRL(t)
	mockCrlFetcher := newMockcrlFetcher(t)
	ctx := t.Context()

	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
		fetchResult{Fetchable: 1, Data: []byte(""), LastModified: time.Time{}, ETag: ""},
		errors.New("fail"),
	)

	crl.fetcher = mockCrlFetcher

	freshMetrics, err := crl.collect(ctx)
	require.NoError(t, err, "Should suppresses error but returns metrics with err set")
	require.Error(t, freshMetrics.err)

	// Check cache
	cachedEntry, ok := state.crlCache.Get(crl.uri)
	assert.True(t, ok, "Error results should be cached")
	require.Error(t, cachedEntry.metrics.err)

	// Call again to check if cache matches via timestamp
	cachedMetrics, err := crl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, freshMetrics.err, cachedMetrics.err)
}

func TestCRL_Parse(t *testing.T) {
	t.Parallel()

	validDER, validPEM := createTestCrlData(t)

	tests := []struct {
		name        string
		input       []byte
		expectError bool
		assertFunc  func(t *testing.T, crl *x509.RevocationList)
	}{
		{
			name:        "Valid DER Encoded CRL",
			input:       validDER,
			expectError: false,
			assertFunc: func(t *testing.T, crl *x509.RevocationList) {
				t.Helper()
				assert.NotNil(t, crl)
				assert.Equal(t, big.NewInt(1), crl.Number, "CRL number should match")
				assert.Len(t, crl.RevokedCertificateEntries, 1, "Should have 1 revoked entry")
			},
		},
		{
			name:        "Valid PEM Encoded CRL",
			input:       validPEM,
			expectError: false,
			assertFunc: func(t *testing.T, crl *x509.RevocationList) {
				t.Helper()
				assert.NotNil(t, crl)
				assert.Equal(t, big.NewInt(1), crl.Number, "CRL number should match")
				assert.Len(t, crl.RevokedCertificateEntries, 1, "Should have 1 revoked entry")
			},
		},
		{
			name:        "Invalid Data",
			input:       []byte("junk"),
			expectError: true,
			assertFunc:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			crl, _ := createTestCRL(t)
			gotCrl, err := crl.parse(tc.input)

			if tc.expectError {
				require.Error(t, err)
				assert.Nil(t, gotCrl)
			} else {
				require.NoError(t, err)
				if tc.assertFunc != nil {
					tc.assertFunc(t, gotCrl)
				}
			}
		})
	}
}

func TestCRL_Collect_Verification(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	startTime := time.Now()

	tests := []struct {
		name                 string
		fetchReturnFetchable int64
		fetchReturnData      []byte
		fetchReturnErr       error
		expectCollectErr     bool
		expectMetricsErr     bool
		wantProcessingStatus int64
	}{
		{
			name:                 "Happy Path",
			fetchReturnFetchable: 1,
			fetchReturnData:      data,
			fetchReturnErr:       nil,
			expectCollectErr:     false,
			expectMetricsErr:     false,
			wantProcessingStatus: crlProcessingStatusSuccess,
		},
		{
			name:                 "Fetch Failed",
			fetchReturnFetchable: 0,
			fetchReturnData:      nil,
			fetchReturnErr:       errors.New("fail"),
			expectCollectErr:     false,
			expectMetricsErr:     true,
			wantProcessingStatus: crlProcessingStatusFetchFailed,
		},
		{
			name:                 "Parse Failed",
			fetchReturnFetchable: 1,
			fetchReturnData:      []byte("junk"),
			fetchReturnErr:       nil,
			expectCollectErr:     false,
			expectMetricsErr:     true,
			wantProcessingStatus: crlProcessingStatusParseFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			crl, _ := createTestCRL(t)
			mockCrlFetcher := newMockcrlFetcher(t)
			ctx := t.Context()

			mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
				fetchResult{Fetchable: tt.fetchReturnFetchable, Data: tt.fetchReturnData},
				tt.fetchReturnErr,
			)

			crl.fetcher = mockCrlFetcher

			metrics, err := crl.collect(ctx)

			if tt.expectCollectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.expectMetricsErr {
				require.Error(t, metrics.err)
			} else {
				require.NoError(t, metrics.err)
			}

			if !tt.expectCollectErr {
				assert.GreaterOrEqual(t, metrics.ts.AsTime(), startTime)
				assert.Equal(t, tt.wantProcessingStatus, metrics.processingStatus)
			}
		})
	}
}

func TestCRL_Collect_RetrySuccessOnRetryableError(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	crl, state := createTestCRL(t)
	ctx := t.Context()
	state.cfg.Crl.Retries = 1
	state.cfg.Crl.RetryInterval = 0

	mockCrlFetcher := newMockcrlFetcher(t)
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
		fetchResult{},
		newRetryableFetchError(errors.New("temporary failure")),
	).Once()
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
		fetchResult{Fetchable: 1, Data: data},
		nil,
	).Once()
	crl.fetcher = mockCrlFetcher

	metrics, err := crl.collect(ctx)
	require.NoError(t, err)
	require.NoError(t, metrics.err)
	assert.Equal(t, crlProcessingStatusSuccess, metrics.processingStatus)
}

func TestCRL_Collect_NoRetryOnPermanentError(t *testing.T) {
	t.Parallel()

	crl, state := createTestCRL(t)
	ctx := t.Context()
	state.cfg.Crl.Retries = 3
	state.cfg.Crl.RetryInterval = 0

	mockCrlFetcher := newMockcrlFetcher(t)
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
		fetchResult{},
		newPermanentFetchError(errors.New("invalid request")),
	).Once()
	crl.fetcher = mockCrlFetcher

	metrics, err := crl.collect(ctx)
	require.NoError(t, err)
	assert.Equal(t, crlProcessingStatusFetchFailed, metrics.processingStatus)
	assert.ErrorContains(t, metrics.err, "invalid request")
}

func TestCRL_Collect_RetryIntervalHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	crl, state := createTestCRL(t)
	state.cfg.Crl.Retries = 1
	state.cfg.Crl.RetryInterval = time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	mockCrlFetcher := newMockcrlFetcher(t)
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
		fetchResult{},
		newRetryableFetchError(errors.New("transient error")),
	).Once()
	crl.fetcher = mockCrlFetcher

	start := time.Now()
	metrics, err := crl.collect(ctx)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Equal(t, crlProcessingStatusFetchFailed, metrics.processingStatus)
	require.ErrorIs(t, metrics.err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 250*time.Millisecond, "retry wait should stop early on context cancellation")
}

func TestCRL_Fetch_UnsupportedProtocols(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		uri             string
		expectErrIs     error
		expectErrString string
	}{
		{
			name:            "FTP",
			uri:             "ftp://127.0.0.1/crl",
			expectErrString: "unsupported protocol: ftp",
		},
		{
			name:            "file",
			uri:             "file://crl.pem",
			expectErrString: "unsupported protocol: file",
		},
		{
			name:        "parse failure",
			uri:         "\n",
			expectErrIs: errCrlParseUri,
		},
	}

	ctx := t.Context()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			crl, _ := createTestCRL(t)
			crl.uri = tc.uri

			res, err := crl.fetcher.fetch(ctx, crl.uri, time.Second, "", time.Time{})

			assert.Equal(t, int64(0), res.Fetchable, "unsupported should return fetchable=false/0")
			if tc.expectErrIs != nil {
				require.ErrorIs(t, err, tc.expectErrIs)
			}
			if tc.expectErrString != "" {
				assert.EqualError(t, err, tc.expectErrString)
			}
		})
	}
}

func TestCRL_Emit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		setupMetrics    func(*crlMetrics)
		expectedMetrics map[string]func(t *testing.T, val int64)
	}{
		{
			name: "Success - All metrics reported",
			setupMetrics: func(m *crlMetrics) {
				m.processingStatus = crlProcessingStatusSuccess
				m.thisUpdateMinutes = -10
				m.nextUpdateMinutes = 10
				m.revokedCertificates = 2
			},
			expectedMetrics: map[string]func(*testing.T, int64){
				"pkiengine.crl.processing_status": func(t *testing.T, v int64) {
					t.Helper()
					assert.Equal(t, crlProcessingStatusSuccess, v)
				},
				"pkiengine.crl.x509.this_update": func(t *testing.T, v int64) {
					t.Helper()
					assert.Negative(t, v)
				},
				"pkiengine.crl.x509.next_update": func(t *testing.T, v int64) {
					t.Helper()
					assert.Positive(t, v)
				},
				"pkiengine.crl.x509.revoked_certificates": func(t *testing.T, v int64) {
					t.Helper()
					assert.Equal(t, int64(2), v)
				},
			},
		},
		{
			name: "Fetch Failure - Only processing status reported",
			setupMetrics: func(m *crlMetrics) {
				m.processingStatus = crlProcessingStatusFetchFailed
			},
			expectedMetrics: map[string]func(*testing.T, int64){
				"pkiengine.crl.processing_status": func(t *testing.T, v int64) {
					t.Helper()
					assert.Equal(t, crlProcessingStatusFetchFailed, v)
				},
			},
		},
		{
			name: "Parse Failure - Only processing status reported",
			setupMetrics: func(m *crlMetrics) {
				m.processingStatus = crlProcessingStatusParseFailed
			},
			expectedMetrics: map[string]func(*testing.T, int64){
				"pkiengine.crl.processing_status": func(t *testing.T, v int64) {
					t.Helper()
					assert.Equal(t, crlProcessingStatusParseFailed, v)
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			startTime := time.Now()
			crl, state := createTestCRL(t)
			metrics := newCrlMetrics()

			tt.setupMetrics(&metrics)

			rb := state.mb.NewResourceBuilder()

			crl.emit(state.mb, metrics)

			res := rb.Emit()
			md := state.mb.Emit(metadata.WithResource(res))

			assert.Equal(t, 1, md.ResourceMetrics().Len())
			metricSlice := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()

			for i := range metricSlice.Len() {
				metric := metricSlice.At(i)
				name := metric.Name()

				assert.Contains(t, tt.expectedMetrics, name, "unexpected metric reported: %q", name)

				dp := metric.Gauge().DataPoints().At(0)
				assert.GreaterOrEqual(t, dp.Timestamp().AsTime(), startTime)

				tt.expectedMetrics[name](t, dp.IntValue())
			}

			assert.Equal(t, len(tt.expectedMetrics), metricSlice.Len(), "different number of metrics reported than expected")
		})
	}
}

func TestCRL_Collect_Concurrency(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	_, data := createTestCrlData(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestCount.Add(1)
		// Simulate latency to ensure overlap
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	sharedCrl, _ := createHTTPTestCRL(t, server.URL)

	const concurrency = 10
	var wg sync.WaitGroup
	startSignal := make(chan struct{})
	errCh := make(chan error, concurrency)

	httpRequestCount.Store(0)

	for range concurrency {
		wg.Go(func() {
			<-startSignal
			_, err := sharedCrl.collect(t.Context())
			errCh <- err
		})
	}

	close(startSignal)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}

	requests := httpRequestCount.Load()
	assert.Equal(t, int32(1), requests, "Singleflight should result in exactly 1 HTTP request")
	assert.EqualValues(t, concurrency-1, sharedCrl.shared.crlCacheHits.Load(), "Singleflight waiters should be counted as cache hits")
	assert.EqualValues(t, 1, sharedCrl.shared.crlCacheMisses.Load(), "Only the request that performed the network fetch should count as a cache miss")
}

// Ensure HTTP CRL URIs are normally checked once per scrape and revalidated next scrape.
func TestCRL_Collect_HttpCaching(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	etag := `"fake-etag"`
	_, data := createTestCrlData(t)
	require.NotEmpty(t, data, "expected test CRL payload")
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

	sharedCrl, state := createHTTPTestCRL(t, server.URL)

	// Initial fetch (200 OK).
	_, err := sharedCrl.collect(t.Context())
	require.NoError(t, err)
	requestsInitial := httpRequestCount.Load()
	assert.Equal(t, int32(1), requestsInitial, "Initial fetch should trigger request")

	// Same scrape: served from cache without extra request.
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	requestsAfterCache := httpRequestCount.Load()
	assert.Equal(t, requestsInitial, requestsAfterCache, "Same scrape should not trigger a second network check")

	// New scrape: one conditional check.
	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	requestsAfterRescrape := httpRequestCount.Load()
	assert.Equal(t, requestsInitial+1, requestsAfterRescrape, "New scrape should trigger one HTTP revalidation")
	assert.True(t, requestHasValidator.Load(), "Revalidation must send If-None-Match")
	assert.EqualValues(t, 2, state.crlCacheHits.Load(), "Expected two cache hits (same-scrape reuse and 304 revalidation)")
	assert.EqualValues(t, 1, state.crlCacheMisses.Load(), "Expected one initial cache miss")
}

// Ensure HTTP CRL caching can be disabled via cache_size=0.
func TestCRL_Collect_HttpCachingDisabled(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	_, data := createTestCrlData(t)
	require.NotEmpty(t, data, "expected test CRL payload")
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

	sharedCrl, state := createHTTPTestCRL(t, server.URL)
	state.crlCache = newNopCrlCache()

	// Initial fetch.
	_, err := sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), httpRequestCount.Load(), "Initial fetch should trigger request")

	// Same scrape: cache disabled should fetch again.
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(2), httpRequestCount.Load(), "Same scrape should trigger a second request when cache is disabled")

	// New scrape: should fetch again without validators.
	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(3), httpRequestCount.Load(), "New scrape should trigger request when cache is disabled")
	assert.False(t, conditionalHeaderSeen.Load(), "Disabled cache must not send conditional headers")
}

// Ensure Last-Modified-only CRL endpoints are conditionally revalidated.
func TestCRL_Collect_HttpCachingLastModifiedOnly(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	_, data := createTestCrlData(t)
	require.NotEmpty(t, data)

	lastModified := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)
	requestHasLastModifiedValidator := atomic.Bool{}
	requestHasETagValidator := atomic.Bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestCount.Add(1)

		if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
			requestHasLastModifiedValidator.Store(true)
			assert.Equal(t, lastModified.Format(http.TimeFormat), ifModifiedSince, "Revalidation should send cached Last-Modified")
			assert.Empty(t, r.Header.Get("If-None-Match"), "ETag validator should be absent when no ETag was cached")
			w.WriteHeader(http.StatusNotModified)

			return
		}

		assert.Empty(t, r.Header.Get("If-Modified-Since"), "Initial request should not send If-Modified-Since without cached validators")
		if r.Header.Get("If-None-Match") != "" {
			requestHasETagValidator.Store(true)
		}

		w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	sharedCrl, state := createHTTPTestCRL(t, server.URL)

	// Initial fetch (200 OK with Last-Modified only).
	_, err := sharedCrl.collect(t.Context())
	require.NoError(t, err)
	requestsInitial := httpRequestCount.Load()
	assert.Equal(t, int32(1), requestsInitial, "Initial fetch should trigger request")

	// Same scrape: served from cache without extra request.
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, requestsInitial, httpRequestCount.Load(), "Same scrape should not trigger a second network check")

	// New scrape: one conditional check using If-Modified-Since.
	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, requestsInitial+1, httpRequestCount.Load(), "New scrape should trigger one HTTP revalidation")
	assert.True(t, requestHasLastModifiedValidator.Load(), "Revalidation must send If-Modified-Since")
	assert.False(t, requestHasETagValidator.Load(), "ETag validator must not be sent when missing")
}

// Ensure Date can bootstrap conditional revalidation when Last-Modified is missing.
func TestCRL_Collect_HttpCachingDateFallback(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	_, data := createTestCrlData(t)
	require.NotEmpty(t, data)

	fallbackDate := time.Date(2025, 1, 3, 1, 0, 0, 0, time.UTC)
	requestHasDateValidator := atomic.Bool{}
	requestHasUnexpectedIfNoneMatch := atomic.Bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestCount.Add(1)

		if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
			requestHasDateValidator.Store(true)
			assert.Equal(t, fallbackDate.Format(http.TimeFormat), ifModifiedSince, "Date fallback should be reused as If-Modified-Since")
			assert.Empty(t, r.Header.Get("If-None-Match"), "If-None-Match should remain empty without an ETag")
			w.WriteHeader(http.StatusNotModified)

			return
		}

		if r.Header.Get("If-None-Match") != "" {
			requestHasUnexpectedIfNoneMatch.Store(true)
		}
		assert.Empty(t, r.Header.Get("If-Modified-Since"), "Initial request should not send If-Modified-Since without cached validators")

		w.Header().Set("Date", fallbackDate.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	sharedCrl, state := createHTTPTestCRL(t, server.URL)

	_, err := sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), httpRequestCount.Load(), "Initial fetch should trigger request")

	// Same scrape should be cache hit.
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), httpRequestCount.Load(), "Same scrape should not trigger a second request")

	// Each new scrape should perform conditional revalidation using Date fallback.
	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(2), httpRequestCount.Load(), "New scrape should trigger conditional revalidation via Date fallback")

	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(3), httpRequestCount.Load(), "Subsequent new scrape should also revalidate conditionally")
	assert.True(t, requestHasDateValidator.Load(), "Date fallback should produce conditional If-Modified-Since requests")
	assert.False(t, requestHasUnexpectedIfNoneMatch.Load(), "If-None-Match should remain empty without an ETag")
}

// Ensure malformed Last-Modified falls back to Date for revalidation.
func TestCRL_Collect_HttpCachingMalformedLastModified(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	_, data := createTestCrlData(t)
	require.NotEmpty(t, data)

	fallbackDate := time.Date(2025, 1, 4, 1, 0, 0, 0, time.UTC)
	requestHasDateFallbackValidator := atomic.Bool{}
	requestHasUnexpectedIfNoneMatch := atomic.Bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestCount.Add(1)

		if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
			requestHasDateFallbackValidator.Store(true)
			assert.Equal(t, fallbackDate.Format(http.TimeFormat), ifModifiedSince, "Malformed Last-Modified should fallback to Date")
			assert.Empty(t, r.Header.Get("If-None-Match"), "If-None-Match should remain empty without an ETag")
			w.WriteHeader(http.StatusNotModified)

			return
		}

		if r.Header.Get("If-None-Match") != "" {
			requestHasUnexpectedIfNoneMatch.Store(true)
		}
		assert.Empty(t, r.Header.Get("If-Modified-Since"), "Initial request should not send If-Modified-Since without cached validators")

		w.Header().Set("Last-Modified", "invalid-date")
		w.Header().Set("Date", fallbackDate.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	sharedCrl, state := createHTTPTestCRL(t, server.URL)

	_, err := sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), httpRequestCount.Load(), "Initial fetch should trigger request")

	// New scrape should revalidate with Date fallback.
	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(2), httpRequestCount.Load(), "Malformed Last-Modified should trigger Date-based revalidation")

	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(3), httpRequestCount.Load(), "Subsequent new scrape should keep using Date-based revalidation")
	assert.True(t, requestHasDateFallbackValidator.Load(), "Date fallback should be used when Last-Modified is malformed")
	assert.False(t, requestHasUnexpectedIfNoneMatch.Load(), "Malformed Last-Modified must not produce If-None-Match")
}

// Ensure endpoints missing Last-Modified, ETag and Date are fully fetched on each new scrape.
func TestCRL_Collect_HttpCachingWithoutAnyValidators(t *testing.T) {
	t.Parallel()

	var httpRequestCount atomic.Int32
	_, data := createTestCrlData(t)
	require.NotEmpty(t, data)

	conditionalHeaderSeen := atomic.Bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequestCount.Add(1)

		if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
			conditionalHeaderSeen.Store(true)
		}

		w.Header()["Date"] = nil // suppress default Date header
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	sharedCrl, state := createHTTPTestCRL(t, server.URL)

	_, err := sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), httpRequestCount.Load(), "Initial fetch should trigger request")

	// Same scrape should be cache hit.
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), httpRequestCount.Load(), "Same scrape should not trigger a second request")

	// Each new scrape should perform a full GET.
	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(2), httpRequestCount.Load(), "New scrape should trigger a full request without any validators")

	advanceScrape(state)
	_, err = sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(3), httpRequestCount.Load(), "Subsequent new scrape should also trigger a full request")
	assert.False(t, conditionalHeaderSeen.Load(), "No conditional headers should be sent when no validators are available")
}

// Ensure LDAP CRL URIs are only cached within a single scrape job.
func TestCRL_Collect_LdapCaching(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	require.NotEmpty(t, data)

	crl, state := createTestCRL(t)
	crl.uri = "ldap://example.com/cn=test?certificateRevocationList"

	mockCrlFetcher := newMockcrlFetcher(t)
	ctx := t.Context()
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
		fetchResult{Fetchable: 1, Data: data},
		nil,
	).Twice()
	crl.fetcher = mockCrlFetcher

	_, err := crl.collect(ctx)
	require.NoError(t, err)

	_, err = crl.collect(ctx)
	require.NoError(t, err)

	// LDAP cache is scrape-local only.
	advanceScrape(state)
	_, err = crl.collect(ctx)
	require.NoError(t, err)
}

// Ensure a 304 response with a missing local cache entry falls back to an unconditional fetch.
func TestCRL_Collect_HTTP304CacheMissFallback(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	require.NotEmpty(t, data)

	var conditionalRequestCount atomic.Int32
	var fullRequestCount atomic.Int32
	etag := `"v1"`

	sharedCrl, state := createTestCRL(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			conditionalRequestCount.Add(1)
			state.crlCache.Remove(sharedCrl.uri)
			w.WriteHeader(http.StatusNotModified)

			return
		}

		fullRequestCount.Add(1)
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	sharedCrl.fetcher = &realCrlFetcher{client: http.DefaultClient}
	sharedCrl.uri = server.URL

	_, err := sharedCrl.collect(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), fullRequestCount.Load())

	advanceScrape(state)
	metrics, err := sharedCrl.collect(t.Context())
	require.NoError(t, err)

	assert.Equal(t, crlProcessingStatusSuccess, metrics.processingStatus)
	assert.Equal(t, int32(1), conditionalRequestCount.Load(), "Expected one conditional request")
	assert.Equal(t, int32(2), fullRequestCount.Load(), "Expected fallback unconditional fetch after cache miss on 304")
	assert.EqualValues(t, 0, state.crlCacheHits.Load(), "304 cache-miss fallback should not count as a hit")
	assert.EqualValues(t, 2, state.crlCacheMisses.Load(), "Initial fetch and fallback re-fetch should both count as misses")
}

// Ensure failed HTTP revalidation is reported as fetch failure.
func TestCRL_Collect_HTTPRevalidationFailureReportsFetchFailure(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	require.NotEmpty(t, data)

	crl, state := createTestCRL(t)
	ctx := t.Context()
	lastModified := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)

	mockCrlFetcher := newMockcrlFetcher(t)
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
		fetchResult{
			Fetchable:    1,
			Data:         data,
			ETag:         `"v1"`,
			LastModified: lastModified,
		},
		nil,
	).Once()
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, `"v1"`, lastModified).Return(
		fetchResult{},
		errors.New("network failure"),
	).Once()
	crl.fetcher = mockCrlFetcher

	_, err := crl.collect(ctx)
	require.NoError(t, err)

	advanceScrape(state)
	metrics, err := crl.collect(ctx)
	require.NoError(t, err)

	assert.Equal(t, crlProcessingStatusFetchFailed, metrics.processingStatus)
	assert.Error(t, metrics.err)
}

// Ensure validators from 304 responses are persisted for subsequent revalidation.
func TestCRL_Collect_HTTP304UpdatesValidators(t *testing.T) {
	t.Parallel()

	data, _ := createTestCrlData(t)
	require.NotEmpty(t, data)

	crl, state := createTestCRL(t)
	ctx := t.Context()

	initialFallbackDate := time.Date(2025, 1, 8, 1, 0, 0, 0, time.UTC)
	upgradedLastModified := time.Date(2025, 1, 9, 1, 0, 0, 0, time.UTC)
	upgradedETag := `"v2"`

	mockCrlFetcher := newMockcrlFetcher(t)
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", time.Time{}).Return(
		fetchResult{
			Fetchable:    1,
			Data:         data,
			LastModified: initialFallbackDate,
		},
		nil,
	).Once()
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, "", initialFallbackDate).Return(
		fetchResult{
			Fetchable:    1,
			ETag:         upgradedETag,
			LastModified: upgradedLastModified,
		},
		errNotModified,
	).Once()
	mockCrlFetcher.On("fetch", ctx, crl.uri, time.Second, upgradedETag, upgradedLastModified).Return(
		fetchResult{
			Fetchable:    1,
			ETag:         upgradedETag,
			LastModified: upgradedLastModified,
		},
		errNotModified,
	).Once()
	crl.fetcher = mockCrlFetcher

	_, err := crl.collect(ctx)
	require.NoError(t, err)

	advanceScrape(state)
	_, err = crl.collect(ctx)
	require.NoError(t, err)

	advanceScrape(state)
	_, err = crl.collect(ctx)
	require.NoError(t, err)
}
