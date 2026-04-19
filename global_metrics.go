package pkienginereceiver

import (
	"sync/atomic"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

type scrapeErrorTotals struct {
	mountErrors  atomic.Int64
	issuerErrors atomic.Int64
}

func (s *pkiEngineScraper) recordGlobalMetrics(
	sharedState *scrapeShared,
	errorTotals *scrapeErrorTotals,
	ts pcommon.Timestamp,
) {
	sharedState.mb.RecordPkiengineCrlCacheHitsDataPoint(ts, sharedState.crlCacheHits.Load())
	sharedState.mb.RecordPkiengineCrlCacheMissesDataPoint(ts, sharedState.crlCacheMisses.Load())
	sharedState.mb.RecordPkiengineCrlCacheEvictionsDataPoint(ts, s.crlEvictionsTotal.Load())
	sharedState.mb.RecordPkiengineMountErrorsDataPoint(ts, errorTotals.mountErrors.Load())
	sharedState.mb.RecordPkiengineIssuerErrorsDataPoint(ts, errorTotals.issuerErrors.Load())
}
