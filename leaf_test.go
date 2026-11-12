package pkienginereceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest/pmetrictest"
)

// Ensures a leaf emits the same metrics as the parsed certificate it was built from.
func TestLeafCertEmitsCertificateValues(t *testing.T) {
	t.Parallel()

	_, certPEM := getTestCertDataWithOU(t, testLeafCommonName, "App")
	crt, err := newCertificate(string(certPEM))
	require.NoError(t, err)
	leaf := newLeafCert(crt, crlURLs{})

	now := time.Now()
	crt.metrics = certificateMetricsAt(now, crt.cert.NotAfter, crt.cert.NotBefore)

	want := createTestScrapeRun(t).mb
	crt.emit(want, metadata.AttributeCertTypeLeaf, "pki/", "")
	got := createTestScrapeRun(t).mb
	leaf.emit(got, now, "pki/")

	require.NoError(t, pmetrictest.CompareMetrics(want.Emit(), got.Emit(), pmetrictest.IgnoreStartTimestamp()))
}

// Counts the datapoints of the named metric.
func countLeafDataPoints(metrics pmetric.Metrics, name string) int {
	count := 0
	rms := metrics.ResourceMetrics()
	for i := range rms.Len() {
		sms := rms.At(i).ScopeMetrics()
		for j := range sms.Len() {
			ms := sms.At(j).Metrics()
			for k := range ms.Len() {
				if ms.At(k).Name() == name {
					count += ms.At(k).Gauge().DataPoints().Len()
				}
			}
		}
	}

	return count
}
