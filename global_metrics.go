package pkienginereceiver

import (
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

type scrapeErrorTotals struct {
	mountErrors  atomic.Int64
	issuerErrors atomic.Int64
}

// Records the scrape-global counters, which are final once collection finished.
func (r *scrapeRun) recordGlobalMetrics(ts pcommon.Timestamp) {
	r.mb.RecordPkiengineCrlCacheHitsDataPoint(ts, r.crls.cacheHits.Load())
	r.mb.RecordPkiengineCrlCacheMissesDataPoint(ts, r.crls.cacheMisses.Load())

	r.mb.RecordPkiengineMountErrorsDataPoint(ts, r.errorTotals.mountErrors.Load())
	r.mb.RecordPkiengineIssuerErrorsDataPoint(ts, r.errorTotals.issuerErrors.Load())

	r.mb.RecordPkiengineRateLimitThrottledDataPoint(ts, r.throttled.Load())
}
