package pkienginereceiver

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/receiver"
	"golang.org/x/sync/singleflight"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

// Common, per-scrape shared state.
type scrapeShared struct {
	cfg             *config
	crlFetchSfg     *singleflight.Group
	crlCache        crlCacheStore
	scrapeStartTime time.Time
	crlCacheHits    atomic.Int64
	crlCacheMisses  atomic.Int64

	mb      *metadata.MetricsBuilder
	mbMutex *sync.Mutex

	crlSeen sync.Map
}

// Creates per-scrape shared resources reused across mounts.
func newScrapeShared(
	cfg *config,
	settings receiver.Settings,
	crlCache crlCacheStore,
) *scrapeShared {
	return &scrapeShared{
		cfg:             cfg,
		crlFetchSfg:     &singleflight.Group{},
		crlCache:        crlCache,
		scrapeStartTime: time.Now(),
		mb: metadata.NewMetricsBuilder(
			cfg.MetricsBuilderConfig,
			settings,
		),
		mbMutex: &sync.Mutex{},
	}
}

// Checks whether this scrape should process the CRL keyed by uri|role|kind.
func (s *scrapeShared) claimCRL(uri string, role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) bool {
	key := crlDedupKey(uri, role, kind)
	_, loaded := s.crlSeen.LoadOrStore(key, struct{}{})

	return !loaded
}

func (s *scrapeShared) shouldCollectCertificates() bool {
	return s.cfg.Metrics.PkiengineMountCertificatesStored.Enabled || s.cfg.Leaf.Enabled
}

func (s *scrapeShared) emitIssuerCertMetrics() bool {
	return metadata.ReceiverPkiengineEmitCertMetricsFromIssuersFeatureGate.IsEnabled()
}

func (s *scrapeShared) emitMount(result mountResult) {
	if result.metrics.storedCertificates == nil {
		return
	}
	s.withMetricsLock(func() {
		s.mb.RecordPkiengineMountCertificatesStoredDataPoint(
			result.metrics.ts,
			*result.metrics.storedCertificates,
			result.path,
		)
	})
}

func (s *scrapeShared) emitIssuer(result issuerResult) {
	if result.skipped {
		return
	}
	s.withMetricsLock(func() {
		if s.emitIssuerCertMetrics() {
			result.certificate.emitCert(s.mb, metadata.AttributeCertTypeIssuer)

			return
		}
		result.certificate.emitIssuer(s.mb)
	})
}

func (s *scrapeShared) emitCert(cert certificate, certType metadata.AttributeCertType) {
	s.withMetricsLock(func() {
		cert.emitCert(s.mb, certType)
	})
}

func (s *scrapeShared) emitCRL(crl *crl, metrics crlMetrics) {
	s.withMetricsLock(func() {
		crl.emit(s.mb, metrics)
	})
}

func (s *scrapeShared) withMetricsLock(emitFn func()) {
	s.mbMutex.Lock()
	defer s.mbMutex.Unlock()
	emitFn()
}

func crlDedupKey(uri string, role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) string {
	var b strings.Builder
	b.Grow(len(uri) + len(role.String()) + len(kind.String()) + 2)
	b.WriteString(uri)
	b.WriteByte('|')
	b.WriteString(role.String())
	b.WriteByte('|')
	b.WriteString(kind.String())

	return b.String()
}
