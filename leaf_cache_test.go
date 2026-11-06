package pkienginereceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ensures lookup splits listed serials into cached leafs and serials to read.
func TestLeafCertCacheLookup(t *testing.T) {
	t.Parallel()

	cache := newLeafCertCache(true)

	cached, uncached := cache.lookup("pki", []string{"01", "02"})
	assert.Empty(t, cached)
	assert.Equal(t, []string{"01", "02"}, uncached)

	cache.add("pki", "01", leafCert{serial: "01"})
	cache.add("pki", "02", leafCert{serial: "02"})
	// Certificates of mounts without a lookup in the current scrape are not stored.
	cache.add("other", "03", leafCert{serial: "03"})

	cached, uncached = cache.lookup("pki", []string{"02", "04"})
	require.Len(t, cached, 1)
	assert.Equal(t, "02", cached[0].serial)
	assert.Equal(t, []string{"04"}, uncached)

	// Serial 01 is no longer listed and dropped.
	cached, uncached = cache.lookup("pki", []string{"01", "02"})
	require.Len(t, cached, 1)
	assert.Equal(t, "02", cached[0].serial)
	assert.Equal(t, []string{"01"}, uncached)

	_, uncached = cache.lookup("other", []string{"03"})
	assert.Equal(t, []string{"03"}, uncached)
}

// Ensures mounts that no longer match are dropped from the cache.
func TestLeafCertCacheRetainMounts(t *testing.T) {
	t.Parallel()

	cache := newLeafCertCache(true)
	for _, mount := range []string{"a", "b"} {
		cache.lookup(mount, []string{"01"})
		cache.add(mount, "01", leafCert{serial: "01"})
	}

	cache.retainMounts([]string{"b"})

	_, uncached := cache.lookup("a", []string{"01"})
	assert.Equal(t, []string{"01"}, uncached)
	cached, _ := cache.lookup("b", []string{"01"})
	assert.Len(t, cached, 1)
}

// Ensures stored certificates are read once and emitted from cache on later scrapes.
func TestScrapeReusesCachedLeafCertificates(t *testing.T) {
	t.Parallel()
	ctx := scrapeTestCtx(t)

	scraper, mockSecretStore := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.Leaf.Enabled = true
	})
	_, leafCertPEM := getTestCertDataWithOU(t, testLeafCommonName, "App")

	mockSecretStore.On("listMountPathsTypePki", ctx).Return([]string{testMountPath}, nil)
	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(newTestClusterConfigData("", ""), nil)
	mockSecretStore.On("listCertificates", ctx, testMountPath).Return([]string{testCertificateSerialKey}, nil).Twice()
	mockSecretStore.On("listIssuers", ctx, testMountPath).Return([]string{}, nil)
	mockSecretStore.On("readCertificate", ctx, testMountPath, testCertificateSerialKey).Return(&certificateData{Certificate: string(leafCertPEM)}, nil).Once()

	require.NoError(t, scraper.start(ctx, newMdatagenNopHost()))

	for range 2 {
		metrics, err := scraper.scrape(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, countLeafDataPoints(metrics, "pkiengine.cert.x509.not_after"))
	}
	mockSecretStore.AssertNumberOfCalls(t, "readCertificate", 1)

	// The certificate is no longer listed and dropped from cache.
	mockSecretStore.On("listCertificates", ctx, testMountPath).Return([]string{}, nil).Once()
	metrics, err := scraper.scrape(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, countLeafDataPoints(metrics, "pkiengine.cert.x509.not_after"))
	_, uncached := scraper.leafCache.lookup(testMountPath, []string{testCertificateSerialKey})
	assert.Equal(t, []string{testCertificateSerialKey}, uncached)

	require.NoError(t, scraper.shutdown(ctx))
}

// Ensures a disabled cache reads every listed serial.
func TestLeafCertCacheDisabled(t *testing.T) {
	t.Parallel()

	cache := newLeafCertCache(false)
	cache.lookup("pki", []string{"01"})
	cache.add("pki", "01", leafCert{serial: "01"})

	cached, uncached := cache.lookup("pki", []string{"01"})
	assert.Empty(t, cached)
	assert.Equal(t, []string{"01"}, uncached)
}
