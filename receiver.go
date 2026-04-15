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
		s.cfg.Crl.Timeout,
		s.cfg.Crl.Retries,
		s.cfg.Crl.RetryInterval,
		s.cfg.Crl.Enabled,
		s.cfg.Crl.ScrapeParent,
		s.crlCache,
		s.cfg.MetricsBuilderConfig,
		s.settings,
		s.cfg.Metrics,
	)

	// Exit early when no mounts match current filters.
	filteredMountPaths, err := getFilteredMounts(ctx, s.logger, s.secretStore, s.cfg)
	if err != nil || len(filteredMountPaths) == 0 {
		return pmetric.NewMetrics(), err
	}

	// Enqueue one root task per mount; each root can fan out more tasks.
	runner := newTaskRunner(ctx, s.cfg.ConcurrencyLimit)
	errorTotals := &scrapeErrorTotals{}

	for _, mountPath := range filteredMountPaths {
		s.enqueueMount(runner, sharedState, mountPath, errorTotals)
	}

	// Wait until no tasks remain.
	runner.wait()

	// Emit global counters after all task-side counters are final.
	s.recordGlobalMetrics(sharedState.mb, sharedState, errorTotals, pcommon.NewTimestampFromTime(time.Now()))

	rb := sharedState.mb.NewResourceBuilder()
	rb.SetEngineAddress(s.cfg.Address)
	rb.SetEngineNamespace(s.cfg.Namespace)

	return sharedState.mb.Emit(metadata.WithResource(rb.Emit())), nil
}

func (s *pkiEngineScraper) recordGlobalMetrics(
	mb *metadata.MetricsBuilder,
	sharedState *scrapeShared,
	errorTotals *scrapeErrorTotals,
	ts pcommon.Timestamp,
) {
	// Capture all aggregate counters at one timestamp for this scrape.
	mb.RecordPkiengineCrlCacheHitsDataPoint(ts, sharedState.crlCacheHits.Load())
	mb.RecordPkiengineCrlCacheMissesDataPoint(ts, sharedState.crlCacheMisses.Load())
	mb.RecordPkiengineCrlCacheEvictionsDataPoint(ts, s.crlEvictionsTotal.Load())
	mb.RecordPkiengineMountErrorsDataPoint(ts, errorTotals.mountErrors.Load())
	mb.RecordPkiengineIssuerErrorsDataPoint(ts, errorTotals.issuerErrors.Load())
}

type metricsSink struct {
	mb *metadata.MetricsBuilder
	mu *sync.Mutex
}

type scrapeErrorTotals struct {
	mountErrors  atomic.Int64
	issuerErrors atomic.Int64
}

// Creates a synchronized metrics sink backed by scrape-shared builder state.
func newMetricsSink(shared *scrapeShared) *metricsSink {
	return &metricsSink{
		mb: shared.mb,
		mu: shared.mbMutex,
	}
}

func (s *metricsSink) EmitMount(result mountResult) {
	if result.metrics.storedCertificates == nil {
		return
	}
	s.withLock(func() {
		s.mb.RecordPkiengineMountCertificatesStoredDataPoint(
			result.metrics.ts,
			*result.metrics.storedCertificates,
			result.path,
		)
	})
}

func (s *metricsSink) EmitIssuer(result issuerResult) {
	s.withLock(func() {
		result.certificate.emit()
	})
}

func (s *metricsSink) EmitCRL(crl *crl, metrics crlMetrics) {
	s.withLock(func() {
		crl.emit(s.mb, metrics)
	})
}

func (s *metricsSink) withLock(emitFn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	emitFn()
}

// Creates mount-scoped state, schedules the mount task and fan-outs issuer
// and CRL subtasks so scrape() can process mounts concurrently.
func (s *pkiEngineScraper) enqueueMount(runner *taskRunner, sharedState *scrapeShared, mountPath string, errorTotals *scrapeErrorTotals) {
	sink := newMetricsSink(sharedState)

	mount := newMount(
		s.logger,
		s.secretStore,
		sharedState,
		mountPath,
	)

	runner.enqueue(func(ctx context.Context) {
		result, err := mount.collect(ctx)
		if err != nil {
			errorTotals.mountErrors.Add(1)
			mount.logger.Warn("failed processing mount", zap.Error(err))

			return
		}

		sink.EmitMount(result)

		// Fan out issuer work after mount-level data is available.
		for _, issuerID := range result.issuerIDs {
			issuer := newIssuer(
				mount.logger,
				s.secretStore,
				sharedState,
				mountPath,
				issuerID,
				result.clusterConfig,
			)

			runner.enqueue(func(ctx context.Context) {
				issuerResult, err := issuer.collect(ctx)
				if err != nil {
					errorTotals.issuerErrors.Add(1)
					issuer.logger.Warn("failed processing issuer", zap.Error(err))

					return
				}
				if issuerResult.skipped {
					return
				}

				sink.EmitIssuer(issuerResult)

				// Fan out CRL processing tasks derived from this issuer.
				for _, task := range issuerResult.crlTasks {
					if !sharedState.claimCRL(task.uri, task.role, task.kind) {
						issuerResult.logger.Debug(
							"skipping duplicate crl in scrape",
							zap.String("crl.uri", task.uri),
							zap.String("crl.role", task.role.String()),
							zap.String("crl.kind", task.kind.String()),
						)

						continue
					}

					runner.enqueue(func(ctx context.Context) {
						crl := newCRL(
							issuerResult.logger,
							sharedState,
							task.uri,
							task.role,
							task.kind,
						)

						metrics, err := crl.collect(ctx)
						if err != nil {
							crl.logger.Warn("failed processing crl", zap.Error(err))

							return
						}

						sink.EmitCRL(crl, metrics)
					})
				}
			})
		}
	})
}
