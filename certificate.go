package pkienginereceiver

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type certificateMetrics struct {
	ts               pcommon.Timestamp
	notAfterMinutes  int64
	notBeforeMinutes int64
}

// Subject attributes of the certificate pre-converted to the slice representation used by the metrics builder.
type certSubjectAttributes struct {
	country            []any
	organization       []any
	organizationalUnit []any
	san                []any
}

type certificate struct {
	cert      *x509.Certificate
	serial    string
	issuerCN  string
	subjectCN string
	metrics   certificateMetrics
	subject   certSubjectAttributes
}

// Parses PEM/DER certificate data and builds an immutable, ready-to-emit value.
func newCertificate(certData string) (certificate, error) {
	cert, err := parseCertificate([]byte(certData))
	if err != nil {
		return certificate{}, err
	}

	return certificate{
		cert:      cert,
		serial:    serialToColonHex(cert.SerialNumber),
		issuerCN:  cert.Issuer.CommonName,
		subjectCN: cert.Subject.CommonName,
		metrics:   certificateMetricsAt(time.Now(), cert.NotAfter, cert.NotBefore),
		subject:   collectSubjectAttributes(cert),
	}, nil
}

// Decodes certificate data, supporting PEM and DER encoding.
func parseCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// Returns all Subject Alternative Name (SAN) entries of the certificate as a sorted string slice.
func certSANs(crt *x509.Certificate) []string {
	san := make([]string, 0, len(crt.DNSNames)+len(crt.IPAddresses)+len(crt.EmailAddresses)+len(crt.URIs))
	san = append(san, crt.DNSNames...)
	for _, ip := range crt.IPAddresses {
		san = append(san, ip.String())
	}
	san = append(san, crt.EmailAddresses...)
	for _, u := range crt.URIs {
		san = append(san, u.String())
	}
	sort.Strings(san)

	return san
}

// Computes the metric values relative to now.
func certificateMetricsAt(now, notAfter, notBefore time.Time) certificateMetrics {
	return certificateMetrics{
		ts:               pcommon.NewTimestampFromTime(now),
		notAfterMinutes:  minutesUntil(now, notAfter),
		notBeforeMinutes: minutesUntil(now, notBefore),
	}
}

// Converts the subject and SAN fields to the slice attributes used by the cert metrics.
func collectSubjectAttributes(crt *x509.Certificate) certSubjectAttributes {
	return certSubjectAttributes{
		country:            toAnySlice(crt.Subject.Country),
		organization:       toAnySlice(crt.Subject.Organization),
		organizationalUnit: toAnySlice(crt.Subject.OrganizationalUnit),
		san:                toAnySlice(certSANs(crt)),
	}
}

// Converts a certificate serial number to a colon-separated hexadecimal string (e.g. "aa:bb:cc").
func serialToColonHex(serial *big.Int) string {
	b := serial.Bytes()
	hex := make([]string, len(b))
	for i, v := range b {
		hex[i] = fmt.Sprintf("%02x", v)
	}

	return strings.Join(hex, ":")
}

// Parses a serial string as hexadecimal and returns it in colon-separated lowercase form.
func normalizeCertificateSerial(serial string) (string, bool) {
	parsed := strings.TrimSpace(serial)
	parsed = strings.ReplaceAll(parsed, ":", "")
	serialInt, ok := big.NewInt(0).SetString(parsed, 16)
	if !ok {
		return "", false
	}

	return serialToColonHex(serialInt), true
}

// Emits the metrics for this certificate.
//
// When certType is AttributeCertTypeLeaf, callers must pass an empty issuerId.
func (c certificate) emit(mb *metadata.MetricsBuilder, certType metadata.AttributeCertType, mount, issuerId string) {
	emitCertificate(mb, c.metrics, certType, c.issuerCN, c.serial, c.subjectCN, c.subject, mount, issuerId)
}

func emitCertificate(
	mb *metadata.MetricsBuilder,
	metrics certificateMetrics,
	certType metadata.AttributeCertType,
	issuerCN, serial, subjectCN string,
	subject certSubjectAttributes,
	mount, issuerId string,
) {
	mb.RecordPkiengineCertX509NotAfterDataPoint(
		metrics.ts,
		metrics.notAfterMinutes,
		certType,
		issuerCN,
		serial,
		subjectCN,
		subject.country,
		subject.organization,
		subject.organizationalUnit,
		subject.san,
		mount,
		issuerId,
	)

	mb.RecordPkiengineCertX509NotBeforeDataPoint(
		metrics.ts,
		metrics.notBeforeMinutes,
		certType,
		issuerCN,
		serial,
		subjectCN,
		subject.country,
		subject.organization,
		subject.organizationalUnit,
		subject.san,
		mount,
		issuerId,
	)
}

// Converts a []string value into a []any.
func toAnySlice(values []string) []any {
	attrs := make([]any, 0, len(values))
	for _, value := range values {
		attrs = append(attrs, value)
	}

	return attrs
}
