package pkienginereceiver

import (
	"testing"
	"time"

	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap/zaptest"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

// Creates per-scrape state with a CRL collector backed by a fresh cache and real fetchers.
func createTestScrapeState(t *testing.T) *scrapeShared {
	t.Helper()
	cfg := NewFactory().CreateDefaultConfig().(*config)
	cfg.Crl.Timeout = time.Second
	cfg.Crl.RetryInterval = 0
	cfg.Leaf.Enabled = true

	crls := newCRLCollector(zaptest.NewLogger(t), cfg.Crl, newCrlCache(), &realCrlFetcher{client: newCrlHTTPClient(cfg.workerCount())})

	return newScrapeShared(cfg, receivertest.NewNopSettings(metadata.Type), crls)
}
