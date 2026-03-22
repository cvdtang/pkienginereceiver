package pkienginereceiver

import (
	"crypto/x509"
	"encoding/pem"
	"math"
	"time"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type certificateMetrics struct {
	ts               pcommon.Timestamp
	notAfterMinutes  int64
	notBeforeMinutes int64
}

type certificate struct {
	state    *scrapeShared
	mount    string
	issuerId string
	raw      string
	crt      *x509.Certificate
	metrics  certificateMetrics
}

func newCertificate(
	state *scrapeShared,
	mount string,
	issuerId string,
	certificateData string,
) certificate {
	return certificate{
		state:    state,
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

func (c *certificate) emit() {
	c.state.mb.RecordPkiengineIssuerX509NotAfterDataPoint(
		c.metrics.ts,
		c.metrics.notAfterMinutes,
		c.issuerId,
		c.crt.Subject.CommonName,
		c.crt.Issuer.CommonName,
		c.mount,
	)

	c.state.mb.RecordPkiengineIssuerX509NotBeforeDataPoint(
		c.metrics.ts,
		c.metrics.notBeforeMinutes,
		c.issuerId,
		c.crt.Subject.CommonName,
		c.crt.Issuer.CommonName,
		c.mount,
	)
}
