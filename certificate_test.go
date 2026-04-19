package pkienginereceiver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Creates test certificate, return DER and PEM format.
func getTestCertData(t *testing.T, cn string, crlURIs ...string) ([]byte, []byte) {
	t.Helper()

	return getTestCertDataWithOU(t, cn, "Platform", crlURIs...)
}

func getTestCertDataWithOU(t *testing.T, cn, ou string, crlURIs ...string) ([]byte, []byte) {
	t.Helper()

	// Generate a temporary Private Key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Define certificate Template
	serialNumber, _ := big.NewInt(0).SetString("12345", 10)
	crlDistributionPoints := make([]string, 0, len(crlURIs))
	for _, crlURI := range crlURIs {
		if crlURI != "" {
			crlDistributionPoints = append(crlDistributionPoints, crlURI)
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"ACME org"},
			OrganizationalUnit: []string{ou},
			CommonName:         cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		CRLDistributionPoints: crlDistributionPoints,
	}

	// Create and Sign the certificate (DER format)
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	require.NoError(t, err)

	// Encode the DER bytes into PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certDER, certPEM
}

func createTestCertificate(t *testing.T) certificate {
	t.Helper()

	issuerId := "58390ed4-aaab-488f-8cc1-cc006df63e37"

	commonName := "ACME org"
	derCert, _ := getTestCertDataWithOU(t, commonName, "Security")

	return newCertificate("pki/", metadata.AttributeCertTypeIssuer, issuerId, string(derCert))
}

func TestCertificate_Parse(t *testing.T) {
	t.Parallel()

	commonName := "ACME org"
	derCert, pemCert := getTestCertData(t, commonName)

	tests := []struct {
		name        string
		certData    []byte
		expectedCN  string
		expectError bool
	}{
		{
			name:        "Valid PEM Format",
			certData:    pemCert,
			expectedCN:  commonName,
			expectError: false,
		},
		{
			name:        "Valid DER Format",
			certData:    derCert,
			expectedCN:  commonName,
			expectError: false,
		},
		{
			name:        "Invalid Data",
			certData:    []byte("junk"),
			expectedCN:  "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			crt := createTestCertificate(t)
			crt.raw = string(tt.certData)

			cert, err := crt.parse()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedCN, cert.Subject.CommonName)
			}
		})
	}
}

func TestCertificate_Collect(t *testing.T) {
	t.Parallel()

	crt := createTestCertificate(t)
	err := crt.collect()
	assert.NoError(t, err)
}

func TestCertificate_Collect_ParseErr(t *testing.T) {
	t.Parallel()

	crt := createTestCertificate(t)
	crt.raw = "junk"

	err := crt.collect()
	assert.Error(t, err)
}

func TestCertificate_CollectMetrics(t *testing.T) {
	t.Parallel()

	crt := createTestCertificate(t)
	err := crt.collect()
	require.NoError(t, err)

	startTime := time.Now()
	metrics := crt.collectMetrics()

	assert.GreaterOrEqual(t, metrics.ts.AsTime(), startTime)

	assert.Positive(t, metrics.notAfterMinutes)
	assert.Negative(t, metrics.notBeforeMinutes)
}

func TestCertificate_Emit(t *testing.T) {
	t.Parallel()

	startTime := time.Now()

	crt := createTestCertificate(t)
	err := crt.collect()
	require.NoError(t, err)

	state := createTestScrapeState(t)
	rb := state.mb.NewResourceBuilder()
	crt.emitIssuer(state.mb)
	crt.emitCert(state.mb, metadata.AttributeCertTypeIssuer)

	res := rb.Emit()
	md := state.mb.Emit(metadata.WithResource(res))
	assert.Equal(t, 1, md.ResourceMetrics().Len())
	metrics := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()

	expectedMetrics := map[string]func(*testing.T, int64){
		"pkiengine.issuer.x509.not_after": func(t *testing.T, v int64) {
			t.Helper()
			assert.Positive(t, v)
		},
		"pkiengine.issuer.x509.not_before": func(t *testing.T, v int64) {
			t.Helper()
			assert.Negative(t, v)
		},
		"pkiengine.cert.x509.not_after": func(t *testing.T, v int64) {
			t.Helper()
			assert.Positive(t, v)
		},
		"pkiengine.cert.x509.not_before": func(t *testing.T, v int64) {
			t.Helper()
			assert.Negative(t, v)
		},
	}

	for i := range metrics.Len() {
		metric := metrics.At(i)
		name := metric.Name()

		validator, ok := expectedMetrics[name]
		require.True(t, ok, "unexpected metric: %s", name)

		assert.Equal(t, 1, metric.Gauge().DataPoints().Len())
		dp := metric.Gauge().DataPoints().At(0)

		assert.GreaterOrEqual(t, dp.Timestamp().AsTime(), startTime)
		validator(t, dp.IntValue())

		if name == "pkiengine.cert.x509.not_after" || name == "pkiengine.cert.x509.not_before" {
			serial, ok := dp.Attributes().Get("cert.x509.serial_number")
			require.True(t, ok)
			require.Equal(t, "30:39", serial.Str())

			subjectCountry, ok := dp.Attributes().Get("cert.x509.subject.country")
			require.True(t, ok)
			require.Equal(t, []any{"US"}, subjectCountry.Slice().AsRaw())

			subjectOrganization, ok := dp.Attributes().Get("cert.x509.subject.organization")
			require.True(t, ok)
			require.Equal(t, []any{"ACME org"}, subjectOrganization.Slice().AsRaw())

			subjectOrganizationalUnit, ok := dp.Attributes().Get("cert.x509.subject.organizational_unit")
			require.True(t, ok)
			require.Equal(t, []any{"Security"}, subjectOrganizationalUnit.Slice().AsRaw())
		}
	}

	assert.Equal(t, len(expectedMetrics), metrics.Len())
}

func TestNormalizeCertificateSerial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		serial string
		want   string
		ok     bool
	}{
		{
			name:   "normalizes mixed case and separators",
			serial: " 0A:bC:dE ",
			want:   "0a:bc:de",
			ok:     true,
		},
		{
			name:   "normalizes non-separated serial",
			serial: "01FF",
			want:   "01:ff",
			ok:     true,
		},
		{
			name:   "rejects invalid input",
			serial: "invalid",
			ok:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := normalizeCertificateSerial(tt.serial)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClassifyCertificateType(t *testing.T) {
	t.Parallel()

	certType, issuerID := classifyCertificateType("aa:bb", map[string]string{
		"aa:bb": "issuer-1",
	})
	assert.Equal(t, metadata.AttributeCertTypeIssuer, certType)
	assert.Equal(t, "issuer-1", issuerID)

	certType, issuerID = classifyCertificateType("cc:dd", map[string]string{
		"aa:bb": "issuer-1",
	})
	assert.Equal(t, metadata.AttributeCertTypeLeaf, certType)
	assert.Empty(t, issuerID)
}
