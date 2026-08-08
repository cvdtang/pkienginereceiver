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
	mount    string
	issuerId string
	raw      string
	crt      *x509.Certificate
	metrics  certificateMetrics
	subject  certSubjectAttributes
}

func newCertificate(
	mount string,
	certType metadata.AttributeCertType,
	issuerId string,
	certificateData string,
) certificate {
	if certType == metadata.AttributeCertTypeLeaf {
		issuerId = ""
	}

	return certificate{
		mount:    mount,
		issuerId: issuerId,
		raw:      certificateData,
	}
}

func (c *certificate) collect() error {
	crt, err := c.parse()
	if err != nil {
		return err
	}
	c.crt = crt

	c.metrics = c.collectMetrics()
	c.subject = c.collectSubjectAttributes()

	return nil
}

// Converts the subject and SAN fields to the slice attributes used by the cert metrics.
func (c *certificate) collectSubjectAttributes() certSubjectAttributes {
	return certSubjectAttributes{
		country:            toAnySlice(c.crt.Subject.Country),
		organization:       toAnySlice(c.crt.Subject.Organization),
		organizationalUnit: toAnySlice(c.crt.Subject.OrganizationalUnit),
		san:                toAnySlice(c.subjectAlternativeNames()),
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

// Returns issuer type and ID when the serial belongs to a known issuer, otherwise it returns leaf type.
func classifyCertificateType(normalizedSerial string, issuerBySerial map[string]string) (metadata.AttributeCertType, string) {
	if issuerID, ok := issuerBySerial[normalizedSerial]; ok {
		return metadata.AttributeCertTypeIssuer, issuerID
	}

	return metadata.AttributeCertTypeLeaf, ""
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

// Parse certificate data, supports PEM and DER encoding.
func (c *certificate) parse() (*x509.Certificate, error) {
	data := []byte(c.raw)

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

func (c *certificate) listBaseCrlDistributionPoints() []string {
	return c.crt.CRLDistributionPoints
}

func (c *certificate) listDeltaCrlDistributionPoints() ([]string, error) {
	return certutil.ParseDeltaCRLExtension(c.crt)
}

func (c *certificate) collectMetrics() certificateMetrics {
	now := pcommon.NewTimestampFromTime(time.Now())
	notAfterMinutes := int64(math.Floor(time.Until(c.crt.NotAfter).Minutes()))
	notBeforeMinutes := int64(math.Floor(time.Until(c.crt.NotBefore).Minutes()))

	metrics := certificateMetrics{
		ts:               now,
		notAfterMinutes:  notAfterMinutes,
		notBeforeMinutes: notBeforeMinutes,
	}

	return metrics
}

func (c *certificate) serial() string {
	if c.crt == nil || c.crt.SerialNumber == nil {
		return ""
	}

	return serialToColonHex(c.crt.SerialNumber)
}

func (c *certificate) emitCert(mb *metadata.MetricsBuilder, certType metadata.AttributeCertType) {
	serialNumber := c.serial()

	mb.RecordPkiengineCertX509NotAfterDataPoint(
		c.metrics.ts,
		c.metrics.notAfterMinutes,
		certType,
		c.crt.Issuer.CommonName,
		serialNumber,
		c.crt.Subject.CommonName,
		c.subject.country,
		c.subject.organization,
		c.subject.organizationalUnit,
		c.subject.san,
		c.mount,
		c.issuerId,
	)

	mb.RecordPkiengineCertX509NotBeforeDataPoint(
		c.metrics.ts,
		c.metrics.notBeforeMinutes,
		certType,
		c.crt.Issuer.CommonName,
		serialNumber,
		c.crt.Subject.CommonName,
		c.subject.country,
		c.subject.organization,
		c.subject.organizationalUnit,
		c.subject.san,
		c.mount,
		c.issuerId,
	)
}

// Returns all Subject Alternative Name (SAN) entries of the certificate as a string slice.
func (c *certificate) subjectAlternativeNames() []string {
	san := make([]string, 0, len(c.crt.DNSNames)+len(c.crt.IPAddresses)+len(c.crt.EmailAddresses)+len(c.crt.URIs))
	san = append(san, c.crt.DNSNames...)
	for _, ip := range c.crt.IPAddresses {
		san = append(san, ip.String())
	}
	san = append(san, c.crt.EmailAddresses...)
	for _, u := range c.crt.URIs {
		san = append(san, u.String())
	}
	sort.Strings(san)

	return san
}
