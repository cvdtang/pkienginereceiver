package pkienginereceiver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
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
		DNSNames:              []string{cn, "alt.example.org"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses:        []string{"admin@example.org"},
		URIs:                  []*url.URL{{Scheme: "https", Host: "ca.example.org"}},
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

	commonName := "ACME org"
	derCert, _ := getTestCertDataWithOU(t, commonName, "Security")

	crt, err := newCertificate(string(derCert))
	require.NoError(t, err)

	return crt
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

			cert, err := parseCertificate(tt.certData)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedCN, cert.Subject.CommonName)
			}
		})
	}
}

func TestCertificate_New(t *testing.T) {
	t.Parallel()

	crt := createTestCertificate(t)
	require.Equal(t, "30:39", crt.serial)
	require.Equal(t, "ACME org", crt.subjectCN)
	require.Equal(t, "ACME org", crt.issuerCN)
}

func TestCertificate_New_ParseErr(t *testing.T) {
	t.Parallel()

	_, err := newCertificate("junk")
	assert.Error(t, err)
}

func TestCertificate_CollectMetrics(t *testing.T) {
	t.Parallel()

	startTime := time.Now()
	_, certDER := getTestCertData(t, "ACME org")
	cert, err := parseCertificate(certDER)
	require.NoError(t, err)
	metrics := collectCertificateMetrics(cert)

	assert.GreaterOrEqual(t, metrics.ts.AsTime(), startTime)

	assert.Positive(t, metrics.notAfterMinutes)
	assert.Negative(t, metrics.notBeforeMinutes)
}

func TestCertificate_Emit(t *testing.T) {
	t.Parallel()

	startTime := time.Now()

	crt := createTestCertificate(t)

	state := createTestScrapeState(t)
	rb := state.mb.NewResourceBuilder()
	crt.emit(state.mb, metadata.AttributeCertTypeIssuer, "pki/", "58390ed4-aaab-488f-8cc1-cc006df63e37")

	res := rb.Emit()
	md := state.mb.Emit(metadata.WithResource(res))
	assert.Equal(t, 1, md.ResourceMetrics().Len())
	metrics := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()

	expectedMetrics := map[string]func(*testing.T, int64){
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

		assertCertEmitAttributes(t, dp,
			"issuer",
			"ACME org",
			"30:39",
			"pki/",
			"58390ed4-aaab-488f-8cc1-cc006df63e37",
			[]any{"US"},
			[]any{"ACME org"},
			[]any{"Security"},
			[]any{"10.0.0.1", "ACME org", "admin@example.org", "alt.example.org", "https://ca.example.org"},
		)
	}

	assert.Equal(t, len(expectedMetrics), metrics.Len())
}

func TestCertificate_Emit_Leaf(t *testing.T) {
	t.Parallel()

	crt := createTestCertificate(t)

	state := createTestScrapeState(t)
	rb := state.mb.NewResourceBuilder()
	crt.emit(state.mb, metadata.AttributeCertTypeLeaf, "pki/", "")

	res := rb.Emit()
	md := state.mb.Emit(metadata.WithResource(res))
	require.Equal(t, 1, md.ResourceMetrics().Len())
	metrics := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()

	// Leaf certificates carry no local issuer, so issuer.id must be present and empty.
	assert.Equal(t, 2, metrics.Len())
	for i := range metrics.Len() {
		metric := metrics.At(i)
		require.Equal(t, 1, metric.Gauge().DataPoints().Len())

		assertCertEmitAttributes(t, metric.Gauge().DataPoints().At(0),
			"leaf",
			"ACME org",
			"30:39",
			"pki/",
			"",
			[]any{"US"},
			[]any{"ACME org"},
			[]any{"Security"},
			[]any{"10.0.0.1", "ACME org", "admin@example.org", "alt.example.org", "https://ca.example.org"},
		)
	}
}

// Asserts the attribute values shared by both x509 certificate metrics on a data point.
func assertCertEmitAttributes(t *testing.T, dp pmetric.NumberDataPoint, certType, issuerCN, serial, mount, issuerID string, country, organization, organizationalUnit, san []any) {
	t.Helper()

	attrs := dp.Attributes()

	assert.Equal(t, certType, requireAttr(t, attrs, "cert.type").Str())
	assert.Equal(t, issuerCN, requireAttr(t, attrs, "cert.x509.issuer.common_name").Str())
	assert.Equal(t, serial, requireAttr(t, attrs, "cert.x509.serial_number").Str())
	assert.Equal(t, mount, requireAttr(t, attrs, "engine.mount").Str())

	if issuerID == "" {
		assert.Empty(t, requireAttr(t, attrs, "issuer.id").Str())
	} else {
		assert.Equal(t, issuerID, requireAttr(t, attrs, "issuer.id").Str())
	}

	assert.Equal(t, country, requireAttr(t, attrs, "cert.x509.subject.country").Slice().AsRaw())
	assert.Equal(t, organization, requireAttr(t, attrs, "cert.x509.subject.organization").Slice().AsRaw())
	assert.Equal(t, organizationalUnit, requireAttr(t, attrs, "cert.x509.subject.organizational_unit").Slice().AsRaw())
	assert.Equal(t, san, requireAttr(t, attrs, "cert.x509.subject.san").Slice().AsRaw())
}

func requireAttr(t *testing.T, attrs pcommon.Map, key string) pcommon.Value {
	t.Helper()

	v, ok := attrs.Get(key)
	require.True(t, ok, "missing attribute %s", key)

	return v
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
