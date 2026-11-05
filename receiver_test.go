package pkienginereceiver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScrapeRunParallelismLimitDefaultsToOne(t *testing.T) {
	t.Parallel()

	scraper, _ := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.ConcurrencyLimit = 0
	})
	shared := newScrapeShared(&scraper.cfg, scraper.settings, newNopCrlCache(), scraper.crlClient)
	run := newScrapeRun(t.Context(), scraper, shared, scraper.secretStore)

	assert.Equal(t, 1, run.parallelismLimit())
}

func TestScrapeRunParallelismLimitUsesConfiguredLimit(t *testing.T) {
	t.Parallel()

	scraper, _ := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.ConcurrencyLimit = 4
	})
	shared := newScrapeShared(&scraper.cfg, scraper.settings, newNopCrlCache(), scraper.crlClient)
	run := newScrapeRun(t.Context(), scraper, shared, scraper.secretStore)

	assert.Equal(t, 4, run.parallelismLimit())
}

func TestNewVaultConfigSizesIdleConnectionPool(t *testing.T) {
	t.Parallel()

	cfg := createDefaultConfig().(*config)
	cfg.ConcurrencyLimit = 256

	assert.Equal(t, 256, newVaultConfig(*cfg).HttpClient.Transport.(*http.Transport).MaxIdleConnsPerHost)
}

func TestScraperCRLClientSizesIdleConnectionPool(t *testing.T) {
	t.Parallel()

	scraper, _ := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.ConcurrencyLimit = 32
	})

	assert.Equal(t, 32, scraper.crlClient.Transport.(*http.Transport).MaxIdleConnsPerHost)
}
