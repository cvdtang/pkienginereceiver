package pkienginereceiver

import (
	"sync"

	"go.opentelemetry.io/collector/receiver"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

// Common, per-scrape shared state.
type scrapeShared struct {
	cfg  *config
	crls *crlCollector

	rateObserver *rateObserver

	mb      *metadata.MetricsBuilder
	mbMutex *sync.Mutex
}

// Creates per-scrape shared resources reused across mounts.
func newScrapeShared(
	cfg *config,
	settings receiver.Settings,
	crls *crlCollector,
) *scrapeShared {
	return &scrapeShared{
		cfg:          cfg,
		crls:         crls,
		rateObserver: newRateObserver(),
		mb: metadata.NewMetricsBuilder(
			cfg.MetricsBuilderConfig,
			settings,
		),
		mbMutex: &sync.Mutex{},
	}
}

func (s *scrapeShared) shouldCollectCertificates() bool {
	return s.cfg.Metrics.PkiengineMountCertificatesStored.Enabled || s.cfg.Leaf.Enabled
}

func (s *scrapeShared) emitMount(result mountResult) {
	if result.storedCertificates == nil {
		return
	}
	s.withMetricsLock(func() {
		s.mb.RecordPkiengineMountCertificatesStoredDataPoint(
			result.ts,
			*result.storedCertificates,
			result.path,
		)
	})
}

func (s *scrapeShared) emitIssuer(result issuerResult) {
	if result.isParent {
		return
	}
	s.withMetricsLock(func() {
		result.certificate.emit(s.mb, metadata.AttributeCertTypeIssuer, result.mountPath, result.id)
	})
}

func (s *scrapeShared) emitCert(cert certificate, certType metadata.AttributeCertType, mount, issuerId string) {
	s.withMetricsLock(func() {
		cert.emit(s.mb, certType, mount, issuerId)
	})
}

// Records the metrics of all claimed CRL series, once all CRL tasks finished.
func (s *scrapeShared) emitCRLs() {
	s.withMetricsLock(func() {
		s.crls.emit(s.mb)
	})
}

func (s *scrapeShared) withMetricsLock(emitFn func()) {
	s.mbMutex.Lock()
	defer s.mbMutex.Unlock()
	emitFn()
}
