package pkienginereceiver

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
	"github.com/hashicorp/vault/sdk/helper/certutil"
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
		metrics:   collectCertificateMetrics(cert),
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

// Computes the emit-time metric values from the parsed certificate.
func collectCertificateMetrics(crt *x509.Certificate) certificateMetrics {
	now := pcommon.NewTimestampFromTime(time.Now())
	notAfterMinutes := int64(math.Floor(time.Until(crt.NotAfter).Minutes()))
	notBeforeMinutes := int64(math.Floor(time.Until(crt.NotBefore).Minutes()))

	return certificateMetrics{
		ts:               now,
		notAfterMinutes:  notAfterMinutes,
		notBeforeMinutes: notBeforeMinutes,
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
	mb.RecordPkiengineCertX509NotAfterDataPoint(
		c.metrics.ts,
		c.metrics.notAfterMinutes,
		certType,
		c.issuerCN,
		c.serial,
		c.subjectCN,
		c.subject.country,
		c.subject.organization,
		c.subject.organizationalUnit,
		c.subject.san,
		mount,
		issuerId,
	)

	mb.RecordPkiengineCertX509NotBeforeDataPoint(
		c.metrics.ts,
		c.metrics.notBeforeMinutes,
		certType,
		c.issuerCN,
		c.serial,
		c.subjectCN,
		c.subject.country,
		c.subject.organization,
		c.subject.organizationalUnit,
		c.subject.san,
		mount,
		issuerId,
	)
}

func (c certificate) listBaseCrlDistributionPoints() []string {
	return c.cert.CRLDistributionPoints
}

func (c certificate) listDeltaCrlDistributionPoints() ([]string, error) {
	return certutil.ParseDeltaCRLExtension(c.cert)
}
