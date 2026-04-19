package pkienginereceiver

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

type pkiEngineScraper struct {
	logger      *zap.Logger
	cfg         config
	secretStore secretStore
	settings    receiver.Settings
	startTime   pcommon.Timestamp

	renewCtx    context.Context
	renewCancel context.CancelFunc
	renewWg     sync.WaitGroup

	crlCache          crlCacheStore
	crlEvictionsTotal atomic.Int64
}

func (s *pkiEngineScraper) start(ctx context.Context, _ component.Host) error {
	// Get derived context that outlives the scrape job for token renewer.
	s.renewCtx, s.renewCancel = context.WithCancel(ctx)

	return nil
}

// Cancels background renewal and waits for renewal workers to exit.
func (s *pkiEngineScraper) shutdown(ctx context.Context) error {
	// Gracefully stop lease renewer goroutine.
	if s.renewCancel != nil {
		s.renewCancel()
	}
	s.renewWg.Wait()

	return nil
}

func newPkiEngineScraper(cfg *config, settings receiver.Settings) (*pkiEngineScraper, error) {
	scraper := &pkiEngineScraper{
		logger: settings.Logger.With(
			zap.String("engine.address", cfg.Address),
			zap.String("engine.namespace", cfg.Namespace),
		),
		cfg:         *cfg,
		secretStore: nil,
		settings:    settings,
		startTime:   pcommon.NewTimestampFromTime(time.Now()),
	}

	// Setup optional CRL cache.
	crlCache := newNopCrlCache()
	if cfg.Crl.Enabled && cfg.Crl.CacheSize > 0 {
		onEvict := func(key string, _ crlCacheEntry) {
			scraper.crlEvictionsTotal.Add(1)
			settings.Logger.Debug("crl evicted from LRU cache", zap.String("key", key))
		}
		backend, err := newLruCrlCache(cfg.Crl.CacheSize, onEvict)
		if err != nil {
			return nil, fmt.Errorf("failed creating CRL cache: %w", err)
		}
		crlCache = backend
	}

	scraper.crlCache = crlCache

	return scraper, nil
}

// Lazily create the secret store client and starts token renewal.
func (s *pkiEngineScraper) ensureSecretStore() error {
	if s.secretStore != nil {
		return nil
	}

	vault, err := newVault(s.renewCtx, s.cfg, s.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize client: %w", err)
	}
	s.secretStore = vault

	s.renewWg.Add(1)
	go s.secretStore.startTokenRenewal(s.renewCtx, &s.renewWg)

	return nil
}

// Executes one scrape cycle across mounts, issuers and CRLs.
func (s *pkiEngineScraper) scrape(ctx context.Context) (pmetric.Metrics, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug("scrape job finished", zap.Duration("duration", time.Since(start)))
	}()

	if err := s.ensureSecretStore(); err != nil {
		return pmetric.NewMetrics(), err
	}
	// Reset per-scrape eviction count before any CRL fetch work starts.
	s.crlEvictionsTotal.Store(0)

	// Shared state across all mount, issuer and CRL tasks.
	sharedState := newScrapeShared(
		&s.cfg,
		s.settings,
		s.crlCache,
	)

	// Exit early when no mounts match current filters.
	filteredMountPaths, err := getFilteredMounts(ctx, s.logger, s.secretStore, s.cfg)
	if err != nil || len(filteredMountPaths) == 0 {
		return pmetric.NewMetrics(), err
	}

	run := newScrapeRun(ctx, s, sharedState)
	run.processMounts(filteredMountPaths)

	// Emit global counters after all task-side counters are final.
	s.recordGlobalMetrics(sharedState, &run.errorTotals, pcommon.NewTimestampFromTime(time.Now()))

	rb := sharedState.mb.NewResourceBuilder()
	rb.SetEngineAddress(s.cfg.Address)
	rb.SetEngineNamespace(s.cfg.Namespace)

	return sharedState.mb.Emit(metadata.WithResource(rb.Emit())), nil
}
