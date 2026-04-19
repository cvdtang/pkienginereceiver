package pkienginereceiver

import (
	"context"
	"sync"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
	"go.uber.org/zap"
)

type scrapeRun struct {
	ctx         context.Context
	scraper     *pkiEngineScraper
	shared      *scrapeShared
	errorTotals scrapeErrorTotals
}

// Creates one per-scrape runtime that owns concurrency and shared counters.
func newScrapeRun(ctx context.Context, scraper *pkiEngineScraper, sharedState *scrapeShared) *scrapeRun {
	return &scrapeRun{
		ctx:     ctx,
		scraper: scraper,
		shared:  sharedState,
	}
}

func (r *scrapeRun) parallelismLimit() int {
	if r.scraper.cfg.ConcurrencyLimit < 1 {
		return 1
	}

	return r.scraper.cfg.ConcurrencyLimit
}

// Fans out mount/issuer/leaf/crl processing through one shared bounded worker pool.
func (r *scrapeRun) processMounts(mountPaths []string) {
	pool := newScrapeTaskPool(r.ctx, r.parallelismLimit())

	for _, mountPath := range mountPaths {
		pool.submit(func() {
			r.handleMountTask(pool, mountPath)
		})
	}

	pool.wait()
}

// Builds mount-local state and schedules issuer work, or immediate leaf planning for issuer-less mounts.
func (r *scrapeRun) handleMountTask(pool *scrapeTaskPool, mountPath string) {
	stageMount := newMount(
		r.scraper.logger,
		r.scraper.secretStore,
		r.shared,
		mountPath,
	)

	result, ok := r.collectMount(stageMount)
	if !ok {
		return
	}

	mountState := newMountWorkState(stageMount, result, r.shared.cfg.Leaf.Enabled)

	for _, issuerID := range result.issuerIDs {
		pool.submit(func() {
			r.handleIssuerTask(pool, mountState, issuerID)
		})
	}

	if r.shared.cfg.Leaf.Enabled && mountState.issuerDone() {
		pool.submit(func() {
			r.handleLeafPlanTask(pool, mountState)
		})
	}
}

// Collects mount-level data and emits mount metrics.
func (r *scrapeRun) collectMount(stageMount mount) (mountResult, bool) {
	result, err := stageMount.collect(r.ctx)
	if err != nil {
		r.errorTotals.mountErrors.Add(1)
		stageMount.logger.Warn("failed processing mount", zap.Error(err))

		return mountResult{}, false
	}

	r.shared.emitMount(result)

	return result, true
}

// Processes one issuer task, updates serial classification state, emits issuer metrics and schedules CRL work.
// Leaf planning is scheduled exactly once by the issuer task that decrements pendingIssuers to zero.
func (r *scrapeRun) handleIssuerTask(pool *scrapeTaskPool, mountState *mountWorkState, issuerID string) {
	if r.shared.cfg.Leaf.Enabled {
		defer func() {
			if mountState.issuerDone() {
				pool.submit(func() {
					r.handleLeafPlanTask(pool, mountState)
				})
			}
		}()
	}

	result, ok := r.collectIssuer(mountState.mount, mountState.clusterCfg, issuerID)
	if !ok {
		return
	}

	mountState.recordIssuerSerial(result.certificateSerial, result.isParent)
	if result.isParent {
		return
	}

	r.shared.emitIssuer(result)
	r.enqueueCRLTasks(pool, result)
}

// Collects one issuer and increments scrape-level issuer errors on failure.
func (r *scrapeRun) collectIssuer(stageMount mount, clusterCfg clusterConfig, issuerID string) (issuerResult, bool) {
	issuer := newIssuer(
		stageMount.logger,
		r.scraper.secretStore,
		r.shared,
		stageMount.path,
		issuerID,
		clusterCfg,
	)

	result, collectErr := issuer.collect(r.ctx)
	if collectErr != nil {
		r.errorTotals.issuerErrors.Add(1)
		issuer.logger.Warn("failed processing issuer", zap.Error(collectErr))

		return issuerResult{}, false
	}

	return result, true
}

func (r *scrapeRun) enqueueCRLTasks(pool *scrapeTaskPool, result issuerResult) {
	for _, crlTask := range result.crlTasks {
		if !r.shared.claimCRL(crlTask.uri, crlTask.role, crlTask.kind) {
			result.logger.Debug(
				"skipping duplicate crl in scrape",
				zap.String("crl.uri", crlTask.uri),
				zap.String("crl.role", crlTask.role.String()),
				zap.String("crl.kind", crlTask.kind.String()),
			)

			continue
		}

		pool.submit(func() {
			r.processCRL(result.logger, crlTask)
		})
	}
}

// Collects and emits one CRL metric set.
func (r *scrapeRun) processCRL(logger *zap.Logger, task crlTask) {
	crl := newCRL(
		logger,
		r.shared,
		task.uri,
		task.role,
		task.kind,
	)

	metrics, err := crl.collect(r.ctx)
	if err != nil {
		crl.logger.Warn("failed processing crl", zap.Error(err))

		return
	}

	r.shared.emitCRL(crl, metrics)
}

func (r *scrapeRun) handleLeafPlanTask(pool *scrapeTaskPool, mountState *mountWorkState) {
	for _, serial := range mountState.leafCandidates() {
		pool.submit(func() {
			r.processCertificate(mountState.mount, serial)
		})
	}
}

// Emits one stored certificate as a leaf certificate.
func (r *scrapeRun) processCertificate(stageMount mount, serial string) {
	storedCert := newStoredCert(
		stageMount.logger,
		r.scraper.secretStore,
		stageMount.path,
		serial,
	)
	storedCertResult, err := storedCert.collect(r.ctx)
	if err != nil {
		storedCert.logger.Warn("failed processing certificate", zap.Error(err))

		return
	}

	storedCertResult.certificate.issuerId = ""
	r.shared.emitCert(storedCertResult.certificate, metadata.AttributeCertTypeLeaf)
}

type mountWorkState struct {
	mount              mount
	clusterCfg         clusterConfig
	certificateSerials []string
	issuerSerials      map[string]struct{}
	parentSerials      map[string]struct{}
	pendingIssuers     int
	mu                 sync.Mutex
}

func newMountWorkState(stageMount mount, result mountResult, leafEnabled bool) *mountWorkState {
	pendingIssuers := len(result.issuerIDs)
	if leafEnabled {
		// Include the mount task in the completion counter so zero-issuer mounts
		// use the same leaf-planning path as mounts with issuers.
		pendingIssuers++
	}

	return &mountWorkState{
		mount:              stageMount,
		clusterCfg:         result.clusterConfig,
		certificateSerials: result.certificateSerials,
		issuerSerials:      make(map[string]struct{}),
		parentSerials:      make(map[string]struct{}),
		pendingIssuers:     pendingIssuers,
	}
}

func (m *mountWorkState) recordIssuerSerial(serial string, isParent bool) {
	if serial == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if isParent {
		m.parentSerials[serial] = struct{}{}
	} else {
		m.issuerSerials[serial] = struct{}{}
	}
}

func (m *mountWorkState) issuerDone() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pendingIssuers <= 0 {
		return false
	}

	m.pendingIssuers--

	return m.pendingIssuers == 0
}

func (m *mountWorkState) leafCandidates() []string {
	m.mu.Lock()
	certificateSerials := append([]string(nil), m.certificateSerials...)
	issuerSerials := make(map[string]struct{}, len(m.issuerSerials))
	for serial := range m.issuerSerials {
		issuerSerials[serial] = struct{}{}
	}
	parentSerials := make(map[string]struct{}, len(m.parentSerials))
	for serial := range m.parentSerials {
		parentSerials[serial] = struct{}{}
	}
	m.mu.Unlock()

	leafSerials := make([]string, 0, len(certificateSerials))
	for _, serial := range certificateSerials {
		normalizedSerial, ok := normalizeCertificateSerial(serial)
		if !ok {
			m.mount.logger.Warn("invalid certificate id, skipping certificate", zap.String("cert.id", serial))

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

type scrapeTaskPool struct {
	ctx context.Context

	mu        sync.Mutex
	cond      *sync.Cond
	queue     []func()
	accepting bool
	pending   int

	workers sync.WaitGroup
}

func newScrapeTaskPool(ctx context.Context, workerCount int) *scrapeTaskPool {
	if workerCount < 1 {
		workerCount = 1
	}

	pool := &scrapeTaskPool{
		ctx:       ctx,
		queue:     make([]func(), 0),
		accepting: true,
	}
	pool.cond = sync.NewCond(&pool.mu)

	pool.workers.Add(workerCount)
	for range workerCount {
		go pool.worker()
	}

	return pool
}

func (p *scrapeTaskPool) submit(taskFn func()) {
	if p.ctx.Err() != nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.accepting {
		return
	}
	p.pending++
	p.queue = append(p.queue, taskFn)
	p.cond.Signal()
}

func (p *scrapeTaskPool) wait() {
	p.mu.Lock()
	for p.pending > 0 {
		p.cond.Wait()
	}
	p.accepting = false
	p.cond.Broadcast()
	p.mu.Unlock()

	p.workers.Wait()
}

func (p *scrapeTaskPool) worker() {
	defer p.workers.Done()

	for {
		p.mu.Lock()
		for len(p.queue) == 0 && p.accepting {
			p.cond.Wait()
		}
		if len(p.queue) == 0 && !p.accepting {
			p.mu.Unlock()

			return
		}
		taskFn := p.queue[0]
		p.queue = p.queue[1:]
		p.mu.Unlock()

		if p.ctx.Err() == nil {
			taskFn()
		}

		p.mu.Lock()
		p.pending--
		p.cond.Broadcast()
		p.mu.Unlock()
	}
}
