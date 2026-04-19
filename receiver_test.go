package pkienginereceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScrapeRunParallelismLimitDefaultsToOne(t *testing.T) {
	t.Parallel()

	scraper, _ := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.ConcurrencyLimit = 0
	})
	shared := newScrapeShared(&scraper.cfg, scraper.settings, newNopCrlCache())
	run := newScrapeRun(t.Context(), scraper, shared)

	assert.Equal(t, 1, run.parallelismLimit())
}

func TestScrapeRunParallelismLimitUsesConfiguredLimit(t *testing.T) {
	t.Parallel()

	scraper, _ := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.ConcurrencyLimit = 4
	})
	shared := newScrapeShared(&scraper.cfg, scraper.settings, newNopCrlCache())
	run := newScrapeRun(t.Context(), scraper, shared)

	assert.Equal(t, 4, run.parallelismLimit())
}
