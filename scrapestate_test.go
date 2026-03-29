package pkienginereceiver

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/receiver/receivertest"
)

func createTestScrapeState(t *testing.T) *scrapeShared {
	t.Helper()
	cache, err := newLruCrlCache(10, nil)
	require.NoError(t, err)

	shared := newScrapeShared(
		time.Second,
		0,
		0,
		true,
		true,
		cache,
		metadata.DefaultMetricsBuilderConfig(),
		receivertest.NewNopSettings(metadata.Type),
		metadata.DefaultMetricsBuilderConfig().Metrics,
	)

	return shared
}

func TestClaimCRLDedupKey(t *testing.T) {
	t.Parallel()

	state := createTestScrapeState(t)

	claimed := state.claimCRL("http://example.test/crl", metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase)
	assert.True(t, claimed)

	duplicate := state.claimCRL("http://example.test/crl", metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase)
	assert.False(t, duplicate)

	// Same URI but different context should be claimable.
	assert.True(t, state.claimCRL("http://example.test/crl", metadata.AttributeCrlRoleIssuer, metadata.AttributeCrlKindBase))
	assert.True(t, state.claimCRL("http://example.test/crl", metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindDelta))
}

func TestClaimCRLConcurrent(t *testing.T) {
	t.Parallel()

	state := createTestScrapeState(t)

	var successCount atomic.Int64
	const workers = 32
	var wg sync.WaitGroup
	wg.Add(workers)

	for range workers {
		go func() {
			defer wg.Done()
			if state.claimCRL("http://example.test/crl", metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase) {
				successCount.Add(1)
			}
		}()
	}

	wg.Wait()

	assert.EqualValues(t, 1, successCount.Load(), "expected only one claim winner for identical uri|role|kind")
}
