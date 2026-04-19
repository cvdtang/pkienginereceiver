package pkienginereceiver

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
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

type certificate struct {
	mount    string
	issuerId string
	raw      string
	crt      *x509.Certificate
	metrics  certificateMetrics
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

	return nil
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

// Deprecated: retained for backward-compatible issuer metrics.
func (c *certificate) emitIssuer(mb *metadata.MetricsBuilder) {
	mb.RecordPkiengineIssuerX509NotAfterDataPoint(
		c.metrics.ts,
		c.metrics.notAfterMinutes,
		c.issuerId,
		c.crt.Subject.CommonName,
		c.crt.Issuer.CommonName,
		c.mount,
	)

	mb.RecordPkiengineIssuerX509NotBeforeDataPoint(
		c.metrics.ts,
		c.metrics.notBeforeMinutes,
		c.issuerId,
		c.crt.Subject.CommonName,
		c.crt.Issuer.CommonName,
		c.mount,
	)
}

func (c *certificate) emitCert(mb *metadata.MetricsBuilder, certType metadata.AttributeCertType) {
	subjectCountry := toAnySlice(c.crt.Subject.Country)
	subjectOrganization := toAnySlice(c.crt.Subject.Organization)
	subjectOrganizationalUnit := toAnySlice(c.crt.Subject.OrganizationalUnit)
	serialNumber := c.serial()

	mb.RecordPkiengineCertX509NotAfterDataPoint(
		c.metrics.ts,
		c.metrics.notAfterMinutes,
		certType,
		c.crt.Issuer.CommonName,
		serialNumber,
		c.crt.Subject.CommonName,
		subjectCountry,
		subjectOrganization,
		subjectOrganizationalUnit,
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
		subjectCountry,
		subjectOrganization,
		subjectOrganizationalUnit,
		c.mount,
		c.issuerId,
	)
}
