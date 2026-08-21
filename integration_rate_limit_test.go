package pkienginereceiver

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// Verifies rate limit handling against a real secret store. A 1 request/s
// quota is applied to the standalone PKI mount and the scraper must both
// observe the throttling (sustained positive pkiengine.rate_limit.throttled
// counters) and still complete a full, error-free scrape through the retry
// loop. The counter value is nondeterministic (it counts 429s per scrape), so
// behavior is asserted with invariants rather than a golden file.
func TestRateLimit(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	for _, img := range integrationMatrixImages {
		for _, tag := range img.tags {
			testName := fmt.Sprintf("image=%s/version=%s", img.subtestImageName, tag)
			t.Run(testName, func(t *testing.T) {
				t.Parallel()
				runRateLimitImageVersion(t, img, tag)
			})
		}
	}
}

// Runs the throttled-scrape phases for one image/version: the non-namespaced
// mode always, plus the namespaced mode for images that support it (OpenBao).
func runRateLimitImageVersion(t *testing.T, img integrationImage, tag string) {
	t.Helper()

	for _, namespaced := range []bool{false, true} {
		if namespaced && !img.runNamespacedTests {
			continue
		}
		t.Run(fmt.Sprintf("namespaced=%t", namespaced), func(t *testing.T) {
			t.Parallel()
			runRateLimitPhase(t, img, tag, namespaced)
		})
	}
}

// Runs one throttled-scrape phase. Each phase gets its own
// engine container and terraform workspace so the quota-creating apply is the
// only apply of the run: the quota resource depends on the certificates and
// issuers (quotas.tf), so the apply itself never executes under throttling.
func runRateLimitPhase(t *testing.T, img integrationImage, tag string, namespaced bool) {
	t.Helper()

	ctx := t.Context()
	start := time.Now()
	defer func() {
		t.Logf("rate limit phase (namespaced=%t) completed in %s", namespaced, time.Since(start))
	}()

	secretStoreContainer := startSecretStoreContainer(t, ctx, img, tag, nil)

	tf := setupTerraform(t, ctx, t.TempDir(), secretStoreContainer)
	secretStoreAddr := resolveSecretStoreAddress(t, ctx, secretStoreContainer)

	vars := tfProjectVars{
		namespaced:          namespaced,
		authTokenTTL:        5,
		authTokenMaxTTL:     30,
		numStandalone:       1,
		numTwoTier:          0,
		numLeaf:             1,
		rateLimitStandalone: true,
	}
	applyTerraform(t, ctx, tf, vars, secretStoreAddr, "")
	vars.renewableToken = terraformOutputString(t, ctx, tf, "renewable_token")

	tc := integrationTestCase{
		name:          "rate-limit",
		cfgMatchRegex: "^pki/standalone/$",
		tfVars:        vars,
		auth:          tokenAuth,
	}

	sink, _, shutdown := startScraperReceiver(t, ctx, &IntegrationSuite{}, tc, secretStoreAddr, false)
	defer shutdown()

	assertThrottledSustained(t, sink)
	assertRateLimitedScrapeCompleted(t, sink)
}

// The throttled counter is per-scrape (reset each scrape cycle), so multiple
// snapshots carrying a positive count prove the quota keeps biting across
// scrape cycles rather than a single one-off 429.
func assertThrottledSustained(t *testing.T, sink *consumertest.MetricsSink) {
	t.Helper()

	assert.Eventually(t, func() bool {
		throttledSnapshots := 0
		for _, metrics := range sink.AllMetrics() {
			if throttledCountFromSnapshot(metrics) > 0 {
				throttledSnapshots++
			}
		}

		return throttledSnapshots >= 2
	}, testRateLimitTimeout, testScrapeInterval)
}

// The retry loop must complete a full scrape despite throttling: the standalone
// mount reports one issuer and one leaf certificate with no processing errors.
func assertRateLimitedScrapeCompleted(t *testing.T, sink *consumertest.MetricsSink) {
	t.Helper()

	assert.Eventually(t, func() bool {
		lastMetrics, ok := latestMetricsSnapshot(sink)
		if !ok {
			return false
		}

		return metricValue(lastMetrics, "pkiengine.mount.certificates_stored") == 2 &&
			metricValue(lastMetrics, "pkiengine.issuer.errors") == 0 &&
			metricValue(lastMetrics, "pkiengine.mount.errors") == 0
	}, testRateLimitTimeout, testScrapeInterval)
}

// Returns the sum of the pkiengine.rate_limit.throttled data points in a snapshot.
func throttledCountFromSnapshot(metrics pmetric.Metrics) int64 {
	return metricValue(metrics, "pkiengine.rate_limit.throttled")
}
