package pkienginereceiver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Tracks the maximum number of concurrently running calls.
type inFlightTracker struct {
	current atomic.Int64
	max     atomic.Int64
}

func (tr *inFlightTracker) enter() {
	current := tr.current.Add(1)
	for {
		prev := tr.max.Load()
		if current <= prev || tr.max.CompareAndSwap(prev, current) {
			return
		}
	}
}

func (tr *inFlightTracker) leave() {
	tr.current.Add(-1)
}

// Ensures leaf certificate reads are bounded by the concurrency limit.
func TestScrapeBoundsLeafCertificateReads(t *testing.T) {
	t.Parallel()
	ctx := scrapeTestCtx(t)

	const leafs = 40
	scraper, mockSecretStore := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.Leaf.Enabled = true
		cfg.ConcurrencyLimit = 2
	})
	_, leafCertPEM := getTestCertDataWithOU(t, testLeafCommonName, "App")

	serials := make([]string, 0, leafs)
	for i := range leafs {
		serials = append(serials, fmt.Sprintf("%02x", i+1))
	}

	var tracker inFlightTracker
	mockSecretStore.On("listMountPathsTypePki", ctx).Return([]string{testMountPath}, nil)
	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(newTestClusterConfigData("", ""), nil)
	mockSecretStore.On("readURLConfiguration", ctx, testMountPath).Return(&urlConfigData{}, nil)
	mockSecretStore.On("listCertificates", ctx, testMountPath).Return(serials, nil)
	mockSecretStore.On("listIssuers", ctx, testMountPath).Return([]string{}, nil)
	mockSecretStore.On("readCertificate", ctx, testMountPath, mock.Anything).Run(func(mock.Arguments) {
		tracker.enter()
		defer tracker.leave()
		time.Sleep(time.Millisecond)
	}).Return(&certificateData{Certificate: string(leafCertPEM)}, nil)

	require.NoError(t, scraper.start(ctx, newMdatagenNopHost()))
	metrics, err := scraper.scrape(ctx)
	require.NoError(t, err)
	require.NoError(t, scraper.shutdown(ctx))

	assert.Equal(t, 1, countLeafDataPoints(metrics, "pkiengine.cert.x509.not_after"))
	mockSecretStore.AssertNumberOfCalls(t, "readCertificate", leafs)
	assert.LessOrEqual(t, tracker.max.Load(), int64(2))
}

// Ensures a cancelled scrape returns and counts the skipped mounts as errors.
func TestScrapeRunStopsOnCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	scraper, _ := createTestScraper(t)
	run := newScrapeRun(scraper, scraper.secretStore)

	done := make(chan []mountOutput)
	go func() { done <- run.collect(ctx, []string{"a/", "b/"}) }()

	select {
	case outputs := <-done:
		assert.Empty(t, outputs)
	case <-time.After(2 * time.Second):
		t.Fatal("collect did not return after context cancellation")
	}
	assert.Equal(t, int64(2), run.errorTotals.mountErrors.Load())
}

func createTestScrapeRun(t *testing.T) *scrapeRun {
	t.Helper()

	scraper, _ := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.Crl.Timeout = time.Second
		cfg.Crl.RetryInterval = 0
		cfg.Leaf.Enabled = true
	})

	return newScrapeRun(scraper, scraper.secretStore)
}

// Ensures a scrape never exceeds the task limit and cannot deadlock.
func TestScrapeTaskLimit(t *testing.T) {
	t.Parallel()

	_, crlDER := createTestCrlData(t)
	_, issuerPEM := getTestCertDataWithOU(t, "Issuer", "CA")
	_, leafPEM := getTestCertDataWithOU(t, testLeafCommonName, "App")

	for _, limit := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			t.Parallel()

			var tracker inFlightTracker
			work := func() {
				tracker.enter()
				defer tracker.leave()
				time.Sleep(200 * time.Microsecond)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				work()
				_, _ = w.Write(crlDER)
			}))
			defer server.Close()

			const mounts, issuers, leafs = 30, 3, 5
			scraper, mockSecretStore := createTestScraperWithConfig(t, func(cfg *config) {
				cfg.Leaf.Enabled = true
				cfg.ConcurrencyLimit = limit
			})
			mountPaths := make([]string, mounts)
			for i := range mounts {
				mountPaths[i] = fmt.Sprintf("pki%d/", i)
			}
			track := func(mock.Arguments) { work() }
			mockSecretStore.On("listMountPathsTypePki", mock.Anything).Return(mountPaths, nil)
			mockSecretStore.On("readClusterConfiguration", mock.Anything, mock.Anything).Run(track).Return(newTestClusterConfigData("", ""), nil)
			mockSecretStore.On("readURLConfiguration", mock.Anything, mock.Anything).Run(track).Return(&urlConfigData{}, nil)
			mockSecretStore.On("listCertificates", mock.Anything, mock.Anything).Run(track).Return([]string{"01", "02", "03", "04", "05"}, nil)
			mockSecretStore.On("listIssuers", mock.Anything, mock.Anything).Run(track).Return([]string{"a", "b", "c"}, nil)
			mockSecretStore.On("readIssuer", mock.Anything, mock.Anything, mock.Anything).Run(track).Return(
				func(_ context.Context, mount string, id string) *issuerData {
					return &issuerData{
						Certificate: string(issuerPEM),
						KeyID:       json.RawMessage(`"key"`),
						// Shared by all mounts, by the issuers of a mount and per issuer.
						CRLDistributionPoints: []string{server.URL + "/shared", server.URL + "/" + mount, server.URL + "/" + mount + id},
					}
				}, nil)
			mockSecretStore.On("readCertificate", mock.Anything, mock.Anything, mock.Anything).Run(track).
				Return(&certificateData{Certificate: string(leafPEM)}, nil)

			ctx := scrapeTestCtx(t)
			require.NoError(t, scraper.start(ctx, newMdatagenNopHost()))
			done := make(chan error, 1)
			go func() {
				_, err := scraper.scrape(ctx)
				done <- err
			}()
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("scrape deadlocked")
			}
			require.NoError(t, scraper.shutdown(ctx))

			assert.Equal(t, int64(limit), tracker.max.Load())
			mockSecretStore.AssertNumberOfCalls(t, "readIssuer", mounts*issuers)
			mockSecretStore.AssertNumberOfCalls(t, "readCertificate", mounts*leafs)
		})
	}
}
