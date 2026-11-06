package pkienginereceiver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func createTestCRL(t *testing.T) (crlTask, *scrapeRun) {
	t.Helper()

	return crlTask{uri: testCrlURI, role: metadata.AttributeCrlRoleSubject, kind: metadata.AttributeCrlKindBase}, createTestScrapeRun(t)
}

var (
	testCrlDataOnce sync.Once
	testCrlDER      []byte
	testCrlPEM      []byte
)

// Generates a real, cryptographically valid CRL DER signed by a CA with the given Common Name.
func createTestCrlForIssuer(t *testing.T, cn string) []byte {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(3 * 24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(2),
				RevocationTime: time.Now(),
			},
		},
	}

	der, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	return der
}

// Generates a CRL DER signed by a throwaway CA with the given revoked entries.
func createTestCrlWithEntries(t *testing.T, entries []x509.RevocationListEntry) []byte {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	crlTemplate := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(3 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}

	der, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	require.NoError(t, err)

	return der
}

// Helper to generate a real, cryptographically valid CRL and return it in both DER and PEM formats.
func createTestCrlData(t *testing.T) ([]byte, []byte) {
	t.Helper()

	testCrlDataOnce.Do(func() {
		testCrlDER = createTestCrlForIssuer(t, "Test CA")

		// Encode to PEM.
		testCrlPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "X509 CRL",
			Bytes: testCrlDER,
		})
	})

	require.NotEmpty(t, testCrlDER)
	require.NotEmpty(t, testCrlPEM)

	return append([]byte(nil), testCrlDER...), append([]byte(nil), testCrlPEM...)
}

func TestCRL_Fetch_UnsupportedProtocols(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		uri             string
		expectErrIs     error
		expectErrString string
	}{
		{
			name:            "FTP",
			uri:             "ftp://127.0.0.1/crl",
			expectErrString: "unsupported protocol: ftp",
		},
		{
			name:            "file",
			uri:             "file://crl.pem",
			expectErrString: "unsupported protocol: file",
		},
		{
			name:        "parse failure",
			uri:         "\n",
			expectErrIs: errCrlParseUri,
		},
	}

	ctx := t.Context()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fetcher := &realCrlFetcher{client: http.DefaultClient}
			res, err := fetcher.fetch(ctx, tc.uri, time.Second, "", time.Time{})

			assert.Equal(t, int64(0), res.Fetchable, "unsupported should return fetchable=false/0")
			if tc.expectErrIs != nil {
				require.ErrorIs(t, err, tc.expectErrIs)
			}
			if tc.expectErrString != "" {
				assert.EqualError(t, err, tc.expectErrString)
			}
		})
	}
}

func TestCreateCRLMetrics_RevokedCertificatesByReason(t *testing.T) {
	t.Parallel()

	der := createTestCrlWithEntries(t, []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(2), RevocationTime: time.Now()},
		{SerialNumber: big.NewInt(3), RevocationTime: time.Now(), ReasonCode: crlReasonKeyCompromise},
		{SerialNumber: big.NewInt(4), RevocationTime: time.Now(), ReasonCode: crlReasonKeyCompromise},
		{SerialNumber: big.NewInt(5), RevocationTime: time.Now(), ReasonCode: crlReasonRemoveFromCRL},
	})

	metrics, err := createCRLMetrics(fetchResult{Fetchable: 1, Data: der})
	require.NoError(t, err)
	// The total metric counts every listed entry, including removeFromCRL.
	assert.Equal(t, int64(4), metrics.revokedCertificates)
	// Every entry is attributed to a reason, including removeFromCRL.
	assert.Equal(t, int64(1), metrics.revokedCertificatesByReason[crlReasonUnspecified])
	assert.Equal(t, int64(2), metrics.revokedCertificatesByReason[crlReasonKeyCompromise])
	assert.Equal(t, int64(1), metrics.revokedCertificatesByReason[crlReasonRemoveFromCRL])
}

func TestCRLReasonSlot(t *testing.T) {
	t.Parallel()

	for code, want := range map[int]int{
		crlReasonUnspecified:         crlReasonUnspecified,
		crlReasonKeyCompromise:       crlReasonKeyCompromise,
		crlReasonUnused:              crlReasonUnspecified,
		crlReasonRemoveFromCRL:       crlReasonRemoveFromCRL,
		crlReasonAACompromise:        crlReasonAACompromise,
		-1:                           crlReasonUnspecified,
		crlRevocationReasonSlots:     crlReasonUnspecified,
		crlRevocationReasonSlots + 5: crlReasonUnspecified,
	} {
		assert.Equal(t, want, crlReasonSlot(code), "reason code %d", code)
	}
}

func TestCRL_Emit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		setupMetrics    func(*crlMetrics)
		expectedMetrics map[string]func(t *testing.T, val int64)
	}{
		{
			name: "Success - All metrics reported",
			setupMetrics: func(m *crlMetrics) {
				m.processingStatus = crlProcessingStatusSuccess
				m.thisUpdate = time.Now().Add(-10 * time.Minute)
				m.nextUpdate = time.Now().Add(10 * time.Minute)
				m.revokedCertificates = 2
			},
			expectedMetrics: map[string]func(*testing.T, int64){
				"pkiengine.crl.processing_status": func(t *testing.T, v int64) {
					t.Helper()
					assert.Equal(t, crlProcessingStatusSuccess, v)
				},
				"pkiengine.crl.x509.this_update": func(t *testing.T, v int64) {
					t.Helper()
					assert.Negative(t, v)
				},
				"pkiengine.crl.x509.next_update": func(t *testing.T, v int64) {
					t.Helper()
					assert.Positive(t, v)
				},
				"pkiengine.crl.x509.revoked_certificates": func(t *testing.T, v int64) {
					t.Helper()
					assert.Equal(t, int64(2), v)
				},
			},
		},
		{
			name: "Fetch Failure - Only processing status reported",
			setupMetrics: func(m *crlMetrics) {
				m.processingStatus = crlProcessingStatusFetchFailed
			},
			expectedMetrics: map[string]func(*testing.T, int64){
				"pkiengine.crl.processing_status": func(t *testing.T, v int64) {
					t.Helper()
					assert.Equal(t, crlProcessingStatusFetchFailed, v)
				},
			},
		},
		{
			name: "Parse Failure - Only processing status reported",
			setupMetrics: func(m *crlMetrics) {
				m.processingStatus = crlProcessingStatusParseFailed
			},
			expectedMetrics: map[string]func(*testing.T, int64){
				"pkiengine.crl.processing_status": func(t *testing.T, v int64) {
					t.Helper()
					assert.Equal(t, crlProcessingStatusParseFailed, v)
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			startTime := time.Now()
			crl, state := createTestCRL(t)
			metrics := newCrlMetrics()

			tt.setupMetrics(&metrics)

			rb := state.mb.NewResourceBuilder()

			crl.emit(state.mb, zaptest.NewLogger(t), metrics)

			res := rb.Emit()
			md := state.mb.Emit(metadata.WithResource(res))

			assert.Equal(t, 1, md.ResourceMetrics().Len())
			metricSlice := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()

			for i := range metricSlice.Len() {
				metric := metricSlice.At(i)
				name := metric.Name()

				assert.Contains(t, tt.expectedMetrics, name, "unexpected metric reported: %q", name)

				dp := metric.Gauge().DataPoints().At(0)
				assert.GreaterOrEqual(t, dp.Timestamp().AsTime(), startTime)

				tt.expectedMetrics[name](t, dp.IntValue())
			}

			assert.Equal(t, len(tt.expectedMetrics), metricSlice.Len(), "different number of metrics reported than expected")
		})
	}
}

func TestCRL_Emit_RevokedCertificatesByReason(t *testing.T) {
	t.Parallel()

	crl, state := createTestCRL(t)
	metrics := newCrlMetrics()
	metrics.processingStatus = crlProcessingStatusSuccess
	metrics.revokedCertificates = 4
	metrics.revokedCertificatesByReason[crlReasonUnspecified] = 1
	metrics.revokedCertificatesByReason[crlReasonKeyCompromise] = 2
	metrics.revokedCertificatesByReason[crlReasonRemoveFromCRL] = 1

	rb := state.mb.NewResourceBuilder()
	crl.emit(state.mb, zaptest.NewLogger(t), metrics)
	res := rb.Emit()
	md := state.mb.Emit(metadata.WithResource(res))

	metricSlice := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()

	var (
		total  int64
		counts = map[string]int64{}
	)
	for i := range metricSlice.Len() {
		metric := metricSlice.At(i)
		switch metric.Name() {
		case "pkiengine.crl.x509.revoked_certificates":
			total = metric.Gauge().DataPoints().At(0).IntValue()
		case "pkiengine.crl.x509.revoked_certificates.reason":
			for j := range metric.Gauge().DataPoints().Len() {
				dp := metric.Gauge().DataPoints().At(j)
				reason := requireAttr(t, dp.Attributes(), "crl.x509.revoked_certificate.reason").Str()
				counts[reason] = dp.IntValue()
			}
		}
	}

	assert.Equal(t, int64(4), total)
	assert.Equal(t, map[string]int64{
		"unspecified":   1,
		"keyCompromise": 2,
		"removeFromCRL": 1,
	}, counts)
}
