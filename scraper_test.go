package pkienginereceiver

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/golden"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest/pmetrictest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

const (
	testError                = "error"
	testMountPath            = "pki/"
	testIssuerID             = "1ae8ce9d-2f70-0761-a465-8c9840a247a2"
	testIssuerCommonName     = "example.org CA"
	testCertificateSerialKey = "17:67:16:b0:b9:45:58:c0:3a:29:e3:cb:d6:98:33:7a:a6:3b:66:c1"
)

var errTest = errors.New(testError)

func createTestScraper(t *testing.T) (*pkiEngineScraper, *mocksecretStore) {
	t.Helper()
	return createTestScraperWithConfig(t, nil)
}

func createTestScraperWithConfig(t *testing.T, configure func(cfg *config)) (*pkiEngineScraper, *mocksecretStore) {
	t.Helper()

	f := NewFactory()
	cfg := f.CreateDefaultConfig().(*config)
	cfg.Auth.AuthToken.Token = "test-token"
	if configure != nil {
		configure(cfg)
	}
	require.NoError(t, cfg.validate())

	scraper := newPkiEngineScraper(cfg, receivertest.NewNopSettings(metadata.Type))
	mockSecretStore := newMocksecretStore(t)
	scraper.secretStore = mockSecretStore

	scraper.logger = zap.NewNop()

	return scraper, mockSecretStore
}

func TestScrapeErrListingMounts(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	scraper, mockSecretStore := createTestScraper(t)
	mockSecretStore.On("listMountPathsTypePki", ctx).Return(nil, errTest)

	err := scraper.start(ctx, newMdatagenNopHost())
	require.NoError(t, err)

	metrics, err := scraper.scrape(ctx)

	assert.EqualError(t, err, "failed to list pki mounts: "+testError)
	assert.Equal(t, pmetric.NewMetrics(), metrics)
}

func TestScrapeNoMounts(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	scraper, mockSecretStore := createTestScraper(t)

	mockSecretStore.On("listMountPathsTypePki", ctx).Return([]string{}, nil)

	err := scraper.start(ctx, newMdatagenNopHost())

	require.NoError(t, err)

	metrics, err := scraper.scrape(ctx)

	assert.NoError(t, err)
	assert.Equal(t, 0, metrics.ResourceMetrics().Len(), "Expected empty metrics")
}

// Happy path
func TestScrape(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	scraper, mockSecretStore := createTestScraper(t)

	// Test data
	expectedFile := filepath.Join("test", "testdata", "mock_happy.yaml")
	_, certPEM := getTestCertData(t, testIssuerCommonName)

	// Mock API
	mockSecretStore.On("listMountPathsTypePki", ctx).Return([]string{testMountPath}, nil)

	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"path":     "",
			"aia_path": "",
		},
	}, nil)

	mockSecretStore.On("listCertificates", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"keys": []interface{}{testCertificateSerialKey},
		},
	}, nil)

	mockSecretStore.On("listIssuers", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"keys": []interface{}{testIssuerID},
		},
	}, nil)

	mockSecretStore.On("readIssuer", ctx, testMountPath, testIssuerID).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"certificate": string(certPEM),
		},
	}, nil)

	// Execution
	err := scraper.start(ctx, newMdatagenNopHost())
	require.NoError(t, err)

	actualMetrics, err := scraper.scrape(ctx)
	assert.NoError(t, err)

	err = scraper.shutdown(ctx)
	require.NoError(t, err)

	// Comparison
	if *update {
		err = golden.WriteMetrics(t, expectedFile, actualMetrics)
		require.NoError(t, err)
	}

	expectedMetrics, err := golden.ReadMetrics(expectedFile)
	require.NoError(t, err)

	assert.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics,
		pmetrictest.IgnoreTimestamp(),
		pmetrictest.IgnoreStartTimestamp(),
	))
}

func TestScrapeMountErrorMetric(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	scraper, mockSecretStore := createTestScraper(t)
	expectedFile := filepath.Join("test", "testdata", "mock_mount_error.yaml")

	mockSecretStore.On("listMountPathsTypePki", ctx).Return([]string{testMountPath}, nil)
	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(nil, errTest)

	err := scraper.start(ctx, newMdatagenNopHost())
	require.NoError(t, err)

	actualMetrics, err := scraper.scrape(ctx)
	require.NoError(t, err)

	err = scraper.shutdown(ctx)
	require.NoError(t, err)

	if *update {
		err = golden.WriteMetrics(t, expectedFile, actualMetrics)
		require.NoError(t, err)
	}

	expectedMetrics, err := golden.ReadMetrics(expectedFile)
	require.NoError(t, err)

	assert.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics,
		pmetrictest.IgnoreTimestamp(),
		pmetrictest.IgnoreStartTimestamp(),
	))
}

func TestScrapeIssuerErrorMetric(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	scraper, mockSecretStore := createTestScraper(t)
	expectedFile := filepath.Join("test", "testdata", "mock_issuer_error.yaml")

	mockSecretStore.On("listMountPathsTypePki", ctx).Return([]string{testMountPath}, nil)

	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"path":     "",
			"aia_path": "",
		},
	}, nil)

	mockSecretStore.On("listCertificates", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"keys": []interface{}{testCertificateSerialKey},
		},
	}, nil)

	mockSecretStore.On("listIssuers", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"keys": []interface{}{testIssuerID},
		},
	}, nil)

	mockSecretStore.On("readIssuer", ctx, testMountPath, testIssuerID).Return(nil, errTest)

	err := scraper.start(ctx, newMdatagenNopHost())
	require.NoError(t, err)

	actualMetrics, err := scraper.scrape(ctx)
	require.NoError(t, err)

	err = scraper.shutdown(ctx)
	require.NoError(t, err)

	if *update {
		err = golden.WriteMetrics(t, expectedFile, actualMetrics)
		require.NoError(t, err)
	}

	expectedMetrics, err := golden.ReadMetrics(expectedFile)
	require.NoError(t, err)

	assert.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics,
		pmetrictest.IgnoreTimestamp(),
		pmetrictest.IgnoreStartTimestamp(),
	))
}

func TestScrapeCRLCacheHitMissMetrics(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	expectedFile := filepath.Join("test", "testdata", "mock_crl_cache_hit_miss.yaml")
	_, crlData := createTestCrlData(t)
	_, certPEM := getTestCertData(t, testIssuerCommonName)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crlData)
	}))
	defer server.Close()

	crlURI := server.URL + "/crl"
	scraper, mockSecretStore := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.ConcurrencyLimit = 1
	})

	mockSecretStore.On("listMountPathsTypePki", ctx).Return([]string{testMountPath}, nil)
	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{"path": "", "aia_path": ""},
	}, nil)
	mockSecretStore.On("listCertificates", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{"keys": []interface{}{testCertificateSerialKey}},
	}, nil)
	mockSecretStore.On("listIssuers", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{"keys": []interface{}{testIssuerID}},
	}, nil)
	mockSecretStore.On("readIssuer", ctx, testMountPath, testIssuerID).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"certificate":                   string(certPEM),
			"crl_distribution_points":       []interface{}{crlURI},
			"delta_crl_distribution_points": []interface{}{crlURI},
			"enable_aia_url_templating":     false,
		},
	}, nil)

	err := scraper.start(ctx, newMdatagenNopHost())
	require.NoError(t, err)

	actualMetrics, err := scraper.scrape(ctx)
	require.NoError(t, err)

	err = scraper.shutdown(ctx)
	require.NoError(t, err)

	normalizeMetrics(actualMetrics)

	if *update {
		err = golden.WriteMetrics(t, expectedFile, actualMetrics)
		require.NoError(t, err)
	}

	expectedMetrics, err := golden.ReadMetrics(expectedFile)
	require.NoError(t, err)

	assert.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics,
		pmetrictest.IgnoreTimestamp(),
		pmetrictest.IgnoreStartTimestamp(),
	))
}

func TestScrapeCRLCacheEvictionsMetric(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	expectedFile := filepath.Join("test", "testdata", "mock_crl_cache_evictions.yaml")
	_, crlData := createTestCrlData(t)
	_, certPEM := getTestCertData(t, testIssuerCommonName)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crlData)
	}))
	defer server.Close()

	scraper, mockSecretStore := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.ConcurrencyLimit = 1
		cfg.Crl.CacheSize = 1
	})

	mockSecretStore.On("listMountPathsTypePki", ctx).Return([]string{testMountPath}, nil)
	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{"path": "", "aia_path": ""},
	}, nil)
	mockSecretStore.On("listCertificates", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{"keys": []interface{}{testCertificateSerialKey}},
	}, nil)
	mockSecretStore.On("listIssuers", ctx, testMountPath).Return(&vaultapi.Secret{
		Data: map[string]interface{}{"keys": []interface{}{testIssuerID}},
	}, nil)
	mockSecretStore.On("readIssuer", ctx, testMountPath, testIssuerID).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"certificate":               string(certPEM),
			"crl_distribution_points":   []interface{}{server.URL + "/crl-a", server.URL + "/crl-b"},
			"enable_aia_url_templating": false,
		},
	}, nil)

	err := scraper.start(ctx, newMdatagenNopHost())
	require.NoError(t, err)

	actualMetrics, err := scraper.scrape(ctx)
	require.NoError(t, err)

	err = scraper.shutdown(ctx)
	require.NoError(t, err)

	normalizeMetrics(actualMetrics)

	if *update {
		err = golden.WriteMetrics(t, expectedFile, actualMetrics)
		require.NoError(t, err)
	}

	expectedMetrics, err := golden.ReadMetrics(expectedFile)
	require.NoError(t, err)

	assert.NoError(t, pmetrictest.CompareMetrics(expectedMetrics, actualMetrics,
		pmetrictest.IgnoreTimestamp(),
		pmetrictest.IgnoreStartTimestamp(),
	))
}

func TestNewPkiEngineScraperCRLCacheSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(cfg *config)
		expectLRU bool
		expectNop bool
	}{
		{
			name: "CRL disabled uses noop cache",
			configure: func(cfg *config) {
				cfg.Crl.Enabled = false
				cfg.Crl.CacheSize = 10
			},
			expectNop: true,
		},
		{
			name: "CRL enabled uses LRU cache",
			configure: func(cfg *config) {
				cfg.Crl.Enabled = true
				cfg.Crl.CacheSize = 10
			},
			expectLRU: true,
		},
		{
			name: "Cache size zero uses noop cache",
			configure: func(cfg *config) {
				cfg.Crl.Enabled = true
				cfg.Crl.CacheSize = 0
			},
			expectNop: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			scraper, _ := createTestScraperWithConfig(t, tt.configure)
			require.NotNil(t, scraper.crlCache)
			if tt.expectLRU {
				_, ok := scraper.crlCache.(*lruCRLCache)
				assert.True(t, ok, "expected lru CRL cache")
			}
			if tt.expectNop {
				_, ok := scraper.crlCache.(*nopCRLCache)
				assert.True(t, ok, "expected noop CRL cache")
			}
		})
	}
}
