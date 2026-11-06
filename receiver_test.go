package pkienginereceiver

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
