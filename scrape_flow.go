package pkienginereceiver

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

// Per-scrape runtime collecting mounts, issuers, CRLs and leaf certificates.
//
// Work is split into tasks: reading a mount, reading an issuer,
// fetching a CRL or reading a leaf certificate, each including its requests and parsing.
// At most workerCount tasks run concurrently. To stay deadlock-free:
//   - a task goroutine is only started once it holds a task slot,
//   - a task never acquires a task slot or waits for other tasks,
//   - only mount goroutines start tasks and wait for them, without holding a task slot.
type scrapeRun struct {
	scraper     *pkiEngineScraper
	cfg         *config
	secretStore secretStore
	crls        *crlCollector
	mb          *metadata.MetricsBuilder

	errorTotals scrapeErrorTotals
	throttled atomic.Int64

	tasks  *semaphore.Weighted
	mounts *semaphore.Weighted

	crlWg sync.WaitGroup
}

// Collected values of one mount.
type mountOutput struct {
	mount   mountResult
	issuers []issuerResult
	leafs   []leafCert
}

// Creates one per-scrape runtime.
func newScrapeRun(scraper *pkiEngineScraper, store secretStore) *scrapeRun {
	cfg := &scraper.cfg
	workers := int64(cfg.workerCount())

	return &scrapeRun{
		scraper:     scraper,
		cfg:         cfg,
		secretStore: store,
		crls:        newCRLCollector(scraper.logger, cfg.Crl, scraper.crlCache, &realCrlFetcher{client: scraper.crlClient}),
		mb:          metadata.NewMetricsBuilder(cfg.MetricsBuilderConfig, scraper.settings),
		tasks:       semaphore.NewWeighted(workers),
		mounts:      semaphore.NewWeighted(workers),
	}
}

// Starts fn as a task once a task slot is free.
// Reports false when the context is done before a slot was free.
func (r *scrapeRun) goTask(ctx context.Context, wg *sync.WaitGroup, fn func()) bool {
	if r.tasks.Acquire(ctx, 1) != nil {
		return false
	}
	wg.Go(func() {
		defer r.tasks.Release(1)
		fn()
	})

	return true
}

// Collects all mounts and waits for the scheduled CRL tasks.
func (r *scrapeRun) collect(ctx context.Context, mountPaths []string) []mountOutput {
	outputs := make([]mountOutput, len(mountPaths))
	collected := make([]bool, len(mountPaths))

	var wg sync.WaitGroup
	for i, mountPath := range mountPaths {
		if r.mounts.Acquire(ctx, 1) != nil {
			r.errorTotals.mountErrors.Add(int64(len(mountPaths) - i))

			break
		}
		wg.Go(func() {
			defer r.mounts.Release(1)
			outputs[i], collected[i] = r.collectMountTree(ctx, mountPath)
		})
	}
	wg.Wait()
	r.crlWg.Wait()

	result := outputs[:0]
	for i := range outputs {
		if collected[i] {
			result = append(result, outputs[i])
		}
	}

	return result
}

// Collects a mount, its issuers and its leaf certificates, and schedules the CRL tasks of its issuers.
func (r *scrapeRun) collectMountTree(ctx context.Context, mountPath string) (mountOutput, bool) {
	stageMount := newMount(
		r.scraper.logger,
		r.secretStore,
		mountPath,
		r.cfg.Metrics.PkiengineMountCertificatesStored.Enabled || r.cfg.Leaf.Enabled,
	)

	result, err := withSlot(ctx, r.tasks, func() (mountResult, error) {
		return stageMount.collect(ctx)
	})
	if err != nil {
		r.errorTotals.mountErrors.Add(1)
		stageMount.logger.Warn("failed processing mount", zap.Error(err))

		return mountOutput{}, false
	}

	output := mountOutput{mount: result}
	issuerSerials := make(map[string]struct{})
	parentSerials := make(map[string]struct{})
	for _, issuer := range r.collectIssuers(ctx, stageMount, result) {
		if issuer.isParent {
			if issuer.certificateSerial != "" {
				parentSerials[issuer.certificateSerial] = struct{}{}
			}

			continue
		}
		issuerSerials[issuer.certificateSerial] = struct{}{}
		output.issuers = append(output.issuers, issuer)
		r.scheduleCRLs(ctx, issuer)
	}

	if r.cfg.Leaf.Enabled {
		serials := leafCandidates(stageMount.logger, result.certificateSerials, issuerSerials, parentSerials)
		output.leafs = r.collectLeafs(ctx, stageMount, serials)
	}

	return output, true
}

// Collects the issuers of a mount as tasks.
func (r *scrapeRun) collectIssuers(ctx context.Context, stageMount mount, result mountResult) []issuerResult {
	issuers := make([]issuerResult, len(result.issuerIDs))
	collected := make([]bool, len(result.issuerIDs))

	var wg sync.WaitGroup
	for i, issuerID := range result.issuerIDs {
		started := r.goTask(ctx, &wg, func() {
			issuers[i], collected[i] = r.collectIssuer(ctx, stageMount, result.clusterConfig, issuerID)
		})
		if !started {
			r.errorTotals.issuerErrors.Add(int64(len(result.issuerIDs) - i))

			break
		}
	}
	wg.Wait()

	output := issuers[:0]
	for i := range issuers {
		if collected[i] {
			output = append(output, issuers[i])
		}
	}

	return output
}

// Collects one issuer and increments scrape-level issuer errors on failure.
func (r *scrapeRun) collectIssuer(ctx context.Context, stageMount mount, clusterCfg clusterConfig, issuerID string) (issuerResult, bool) {
	issuer := newIssuer(
		stageMount.logger,
		r.secretStore,
		r.cfg.Crl,
		stageMount.path,
		issuerID,
		clusterCfg,
	)

	result, collectErr := issuer.collect(ctx)
	if collectErr != nil {
		r.errorTotals.issuerErrors.Add(1)
		issuer.logger.Warn("failed processing issuer", zap.Error(collectErr))

		return issuerResult{}, false
	}

	return result, true
}

// Claims the CRL series of an issuer and starts one CRL task per URI not yet collected in this scrape.
func (r *scrapeRun) scheduleCRLs(ctx context.Context, result issuerResult) {
	for _, task := range result.crlTasks {
		claimed, collect := r.crls.claim(task)
		if !claimed {
			result.logger.Debug(
				"skipping duplicate crl in scrape",
				zap.String("crl.uri", task.uri),
				zap.String("crl.role", task.role.String()),
				zap.String("crl.kind", task.kind.String()),
			)

			continue
		}
		if !collect {
			continue
		}

		logger := result.logger.WithLazy(zap.String("crl.uri", task.uri))
		r.goTask(ctx, &r.crlWg, func() {
			if _, err := r.crls.collect(ctx, logger, task.uri); err != nil {
				logger.Warn("failed processing crl", zap.Error(err))
			}
		})
	}
}

// Reads the leaf certificates of a mount as tasks.
func (r *scrapeRun) collectLeafs(ctx context.Context, stageMount mount, serials []string) []leafCert {
	var leafs []leafCert

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, serial := range serials {
		started := r.goTask(ctx, &wg, func() {
			crt, err := readStoredCertificate(ctx, r.secretStore, stageMount.path, serial)
			if err != nil {
				stageMount.logger.Warn("failed processing certificate", zap.String("cert.serial", serial), zap.Error(err))

				return
			}

			leaf := newLeafCert(crt)

			mu.Lock()
			leafs = append(leafs, leaf)
			mu.Unlock()
		})
		if !started {
			break
		}
	}
	wg.Wait()

	return leafs
}

// Records all collected values to the metrics builder.
func (r *scrapeRun) emit(outputs []mountOutput) {
	now := time.Now()

	for _, output := range outputs {
		if output.mount.storedCertificates != nil {
			r.mb.RecordPkiengineMountCertificatesStoredDataPoint(
				output.mount.ts,
				*output.mount.storedCertificates,
				output.mount.path,
			)
		}
		for _, issuer := range output.issuers {
			issuer.certificate.emit(r.mb, metadata.AttributeCertTypeIssuer, issuer.mountPath, issuer.id)
		}
		for i := range output.leafs {
			output.leafs[i].emit(r.mb, now, output.mount.path)
		}
	}

	r.crls.emit(r.mb)
}

// Returns the stored certificate serials which are neither issuers nor copied parent issuers of the mount.
func leafCandidates(logger *zap.Logger, certificateSerials []string, issuerSerials, parentSerials map[string]struct{}) []string {
	leafSerials := make([]string, 0, len(certificateSerials))
	for _, serial := range certificateSerials {
		normalizedSerial, ok := normalizeCertificateSerial(serial)
		if !ok {
			logger.Warn("invalid certificate id, skipping certificate", zap.String("cert.id", serial))

			continue
		}
		if _, isParent := parentSerials[normalizedSerial]; isParent {
			continue
		}
		if _, isIssuer := issuerSerials[normalizedSerial]; isIssuer {
			continue
		}

		leafSerials = append(leafSerials, serial)
	}

	return leafSerials
}

// Runs fn while holding one slot of the semaphore.
func withSlot[T any](ctx context.Context, sem *semaphore.Weighted, fn func() (T, error)) (T, error) {
	if err := sem.Acquire(ctx, 1); err != nil {
		var zero T

		return zero, err
	}
	defer sem.Release(1)

	return fn()
}
