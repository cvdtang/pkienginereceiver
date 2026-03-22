package pkienginereceiver

import (
	"net/http"
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
	crlFetchSfg           *singleflight.Group
	crlFetchTimeout       time.Duration
	crlFetchRetries       uint
	crlFetchRetryInterval time.Duration
	crlEnabled            bool
	crlScrapeParent       bool
	crlCache              crlCacheStore
	httpClient            *http.Client
	scrapeStartTime       time.Time
	crlCacheHits          atomic.Int64
	crlCacheMisses        atomic.Int64

	metricsCfg metadata.MetricsConfig

	mb      *metadata.MetricsBuilder
	mbMutex *sync.Mutex

	crlSeenMu sync.Mutex
	crlSeen   map[string]struct{}
}

// Creates per-scrape shared resources reused across mounts.
func newScrapeShared(
	crlFetchTimeout time.Duration,
	crlFetchRetries uint,
	crlFetchRetryInterval time.Duration,
	crlEnabled bool,
	crlScrapeParent bool,
	crlCache crlCacheStore,
	metricsBuilderCfg metadata.MetricsBuilderConfig,
	settings receiver.Settings,
	metricsCfg metadata.MetricsConfig,
) (*scrapeShared, error) {
	return &scrapeShared{
		crlFetchSfg:           &singleflight.Group{},
		crlFetchTimeout:       crlFetchTimeout,
		crlFetchRetries:       crlFetchRetries,
		crlFetchRetryInterval: crlFetchRetryInterval,
		crlEnabled:            crlEnabled,
		crlScrapeParent:       crlScrapeParent,
		crlCache:              crlCache,
		httpClient:            http.DefaultClient,
		scrapeStartTime:       time.Now(),
		metricsCfg:            metricsCfg,
		mb: metadata.NewMetricsBuilder(
			metricsBuilderCfg,
			settings,
		),
		mbMutex: &sync.Mutex{},
		crlSeen: make(map[string]struct{}),
	}, nil
}

// Checks whether this scrape should process the CRL keyed by uri|role|kind.
func (s *scrapeShared) claimCRL(uri string, role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) bool {
	key := crlDedupKey(uri, role, kind)

	s.crlSeenMu.Lock()
	defer s.crlSeenMu.Unlock()

	if _, exists := s.crlSeen[key]; exists {
		return false
	}
	s.crlSeen[key] = struct{}{}
	return true
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
