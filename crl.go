package pkienginereceiver

import (
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.uber.org/zap"
)

const (
	crlProcessingStatusFetchFailed int64 = 0
	crlProcessingStatusParseFailed int64 = 1
	crlProcessingStatusSuccess     int64 = 2
)

// RFC 5280 Section 5.3.1 CRLReason values.
const (
	crlReasonUnspecified          = 0
	crlReasonKeyCompromise        = 1
	crlReasonCACompromise         = 2
	crlReasonAffiliationChanged   = 3
	crlReasonSuperseded           = 4
	crlReasonCessationOfOperation = 5
	crlReasonCertificateHold      = 6
	// RFC 5280 "unused" code, folded into unspecified (no metric attribute).
	crlReasonUnused             = 7
	crlReasonRemoveFromCRL      = 8
	crlReasonPrivilegeWithdrawn = 9
	crlReasonAACompromise       = 10

	// Bounds the per-reason counters indexed by RFC 5280 reason code.
	crlRevocationReasonSlots = 11
)

type crlMetrics struct {
	ts                          pcommon.Timestamp
	issuerCommonName            string
	processingStatus            int64
	thisUpdate                  time.Time
	nextUpdate                  time.Time
	revokedCertificates         int64
	revokedCertificatesByReason [crlRevocationReasonSlots]int64
	err                         error
}

// Converts an absolute timestamp to the whole minutes remaining from now.
func minutesUntil(now, t time.Time) int64 {
	return int64(math.Floor(t.Sub(now).Minutes()))
}

// Maps an RFC 5280 Section 5.3.1 reason code to its metric attribute value.
type crlRevocationReason struct {
	code int
	attr metadata.AttributeCrlX509RevokedCertificateReason
}

var crlRevocationReasons = []crlRevocationReason{
	{crlReasonUnspecified, metadata.AttributeCrlX509RevokedCertificateReasonUnspecified},
	{crlReasonKeyCompromise, metadata.AttributeCrlX509RevokedCertificateReasonKeyCompromise},
	{crlReasonCACompromise, metadata.AttributeCrlX509RevokedCertificateReasonCACompromise},
	{crlReasonAffiliationChanged, metadata.AttributeCrlX509RevokedCertificateReasonAffiliationChanged},
	{crlReasonSuperseded, metadata.AttributeCrlX509RevokedCertificateReasonSuperseded},
	{crlReasonCessationOfOperation, metadata.AttributeCrlX509RevokedCertificateReasonCessationOfOperation},
	{crlReasonCertificateHold, metadata.AttributeCrlX509RevokedCertificateReasonCertificateHold},
	{crlReasonRemoveFromCRL, metadata.AttributeCrlX509RevokedCertificateReasonRemoveFromCRL},
	{crlReasonPrivilegeWithdrawn, metadata.AttributeCrlX509RevokedCertificateReasonPrivilegeWithdrawn},
	{crlReasonAACompromise, metadata.AttributeCrlX509RevokedCertificateReasonAACompromise},
}

// Initializes CRL metrics with the current timestamp.
func newCrlMetrics() crlMetrics {
	return crlMetrics{
		ts:               pcommon.NewTimestampFromTime(time.Now()),
		processingStatus: crlProcessingStatusFetchFailed,
	}
}

// One emitted CRL series, identified by its URI, role and kind.
type crlTask struct {
	uri  string
	role metadata.AttributeCrlRole
	kind metadata.AttributeCrlKind
}

// Extracts the lowercase CRL URI scheme and reports whether it is supported.
func crlScheme(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", true
	}

	scheme := strings.ToLower(u.Scheme)

	return scheme, isSupportedCrlScheme(scheme)
}

// Reports whether the CRL scheme is supported.
func isSupportedCrlScheme(scheme string) bool {
	return isHttpCrlScheme(scheme) || isLdapCrlScheme(scheme)
}

// Reports whether the CRL scheme is HTTP(S).
func isHttpCrlScheme(scheme string) bool {
	return scheme == httpScheme || scheme == httpsScheme
}

// Reports whether the CRL scheme is LDAP(S).
func isLdapCrlScheme(scheme string) bool {
	return scheme == ldapScheme || scheme == ldapsScheme
}

// Parses fetched CRL data and maps it to metric values.
func createCRLMetrics(res fetchResult) (crlMetrics, error) {
	metrics := newCrlMetrics()
	if res.Fetchable == 0 {
		return metrics, nil
	}

	summary, err := summarizeCRL(res.Data)
	if err != nil {
		metrics.processingStatus = crlProcessingStatusParseFailed

		return metrics, err
	}

	metrics.processingStatus = crlProcessingStatusSuccess
	metrics.issuerCommonName = summary.issuerCommonName
	metrics.nextUpdate = summary.nextUpdate
	metrics.thisUpdate = summary.thisUpdate
	metrics.revokedCertificates = summary.revokedCertificates
	metrics.revokedCertificatesByReason = summary.revokedCertificatesByReason

	return metrics, nil
}

// Maps a reason code to its counter slot.
// Codes outside the RFC table fold into `unspecified`.
func crlReasonSlot(code int) int {
	if code < 0 || code >= crlRevocationReasonSlots || code == crlReasonUnused {
		return crlReasonUnspecified
	}

	return code
}

// Records CRL metrics to the metrics builder.
func (t crlTask) emit(mb *metadata.MetricsBuilder, logger *zap.Logger, metrics crlMetrics) {
	mb.RecordPkiengineCrlProcessingStatusDataPoint(
		metrics.ts,
		metrics.processingStatus,
		t.role,
		t.kind,
		t.uri,
	)
	if metrics.processingStatus != crlProcessingStatusSuccess {
		switch metrics.processingStatus {
		case crlProcessingStatusFetchFailed:
			logger.Debug("failed fetching CRL, omitting other metrics", zap.Error(metrics.err))
		case crlProcessingStatusParseFailed:
			logger.Debug("failed parsing CRL, omitting other metrics", zap.Error(metrics.err))
		default:
			logger.Debug(
				"unknown CRL processing status, omitting other metrics",
				zap.Int64("processing_status", metrics.processingStatus),
				zap.Error(metrics.err),
			)
		}

		return
	}

	now := time.Now()
	mb.RecordPkiengineCrlX509ThisUpdateDataPoint(
		metrics.ts,
		minutesUntil(now, metrics.thisUpdate),
		t.uri,
		t.role,
		t.kind,
		metrics.issuerCommonName,
	)

	mb.RecordPkiengineCrlX509NextUpdateDataPoint(
		metrics.ts,
		minutesUntil(now, metrics.nextUpdate),
		t.uri,
		t.role,
		t.kind,
		metrics.issuerCommonName,
	)

	// The total includes entries with reason `removeFromCRL`.
	mb.RecordPkiengineCrlX509RevokedCertificatesDataPoint(
		metrics.ts,
		metrics.revokedCertificates,
		t.uri,
		t.role,
		t.kind,
		metrics.issuerCommonName,
	)

	for _, reason := range crlRevocationReasons {
		count := metrics.revokedCertificatesByReason[reason.code]
		if count == 0 {
			continue
		}

		mb.RecordPkiengineCrlX509RevokedCertificatesReasonDataPoint(
			metrics.ts,
			count,
			t.uri,
			t.role,
			t.kind,
			metrics.issuerCommonName,
			reason.attr,
		)
	}
}
