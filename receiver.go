package pkienginereceiver

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

type pkiEngineScraper struct {
	logger    *zap.Logger
	cfg       config
	settings  receiver.Settings
	startTime pcommon.Timestamp

	storeMu     sync.Mutex
	secretStore secretStore

	renewCtx    context.Context
	renewCancel context.CancelFunc
	renewWg     sync.WaitGroup

	crlCache  crlCacheStore
	crlClient *http.Client

	leafCache *leafCertCache
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

	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	if s.secretStore != nil {
		s.secretStore.closeIdleConnections()
	}

	return nil
}

func newPkiEngineScraper(cfg *config, settings receiver.Settings) *pkiEngineScraper {
	scraper := &pkiEngineScraper{
		logger: settings.Logger.With(
			zap.String("engine.address", cfg.Address),
			zap.String("engine.namespace", cfg.Namespace),
		),
		cfg:         *cfg,
		secretStore: nil,
		settings:    settings,
		startTime:   pcommon.NewTimestampFromTime(time.Now()),
		crlClient:   newCrlHTTPClient(cfg.workerCount()),
		leafCache:   newLeafCertCache(cfg.Leaf.Cache.Enabled),
	}

	if cfg.Crl.CacheSize != nil {
		scraper.logger.Warn("crl.cache_size is deprecated and ignored unless 0, use crl.cache.enabled instead")
		if *cfg.Crl.CacheSize == 0 {
			scraper.cfg.Crl.Cache.Enabled = false
		}
	}

	scraper.crlCache = newNopCrlCache()
	if scraper.cfg.Crl.Enabled && scraper.cfg.Crl.Cache.Enabled {
		scraper.crlCache = newCrlCache()
	}

	return scraper
}

// Lazily create the secret store client and starts token renewal.
func (s *pkiEngineScraper) ensureSecretStore() (secretStore, error) {
	s.storeMu.Lock()
	defer s.storeMu.Unlock()

	if s.secretStore != nil {
		return s.secretStore, nil
	}

	vault, err := newVault(s.renewCtx, s.cfg, s.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client: %w", err)
	}
	s.secretStore = vault

	s.renewWg.Go(func() {
		if stopped := vault.runTokenRenewal(s.renewCtx); stopped {
			s.dropSecretStore(vault)
		}
	})

	return vault, nil
}

// Drops the client so the next scrape authenticates again, unless it was replaced already.
func (s *pkiEngineScraper) dropSecretStore(store secretStore) {
	s.storeMu.Lock()
	defer s.storeMu.Unlock()

	if s.secretStore == store {
		s.logger.Warn("token renewal stopped, the client is re-created on the next scrape")
		s.secretStore = nil
	}
}

// Executes one scrape cycle across mounts, issuers and CRLs.
func (s *pkiEngineScraper) scrape(ctx context.Context) (pmetric.Metrics, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug("scrape job finished", zap.Duration("duration", time.Since(start)))
	}()

	store, err := s.ensureSecretStore()
	if err != nil {
		return pmetric.NewMetrics(), err
	}
	defer s.crlClient.CloseIdleConnections()

	run := newScrapeRun(s, store)
	ctx = withRateLimitCounter(ctx, &run.throttled)

	// Exit early when no mounts match current filters.
	filteredMountPaths, err := getFilteredMounts(ctx, s.logger, store, s.cfg)
	if err != nil || len(filteredMountPaths) == 0 {
		return pmetric.NewMetrics(), err
	}

	outputs := run.collect(ctx, filteredMountPaths)
	s.leafCache.retainMounts(filteredMountPaths)
	run.crls.pruneCache()
	run.emit(outputs)

	// Emit global counters after all task-side counters are final.
	run.recordGlobalMetrics(pcommon.NewTimestampFromTime(time.Now()))

	rb := run.mb.NewResourceBuilder()
	rb.SetEngineAddress(s.cfg.Address)
	rb.SetEngineNamespace(s.cfg.Namespace)

	return run.mb.Emit(metadata.WithResource(rb.Emit())), nil
}
