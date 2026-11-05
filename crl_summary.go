package pkienginereceiver

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// DER encoded OID 2.5.29.21 (id-ce-cRLReasons) without tag and length.
var oidExtensionReasonCodeDER = []byte{0x55, 0x1d, 0x15}

// Tag of the TBSCertList crlExtensions field.
var crlExtensionsTag = cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()

// Values of a CRL required for metrics.
type crlSummary struct {
	issuerCommonName            string
	thisUpdate                  time.Time
	nextUpdate                  time.Time
	revokedCertificates         int64
	revokedCertificatesByReason [crlRevocationReasonSlots]int64
}

// Decodes CRL bytes from PEM or DER format and summarizes it without materializing the revoked certificate entries.
func summarizeCRL(data []byte) (crlSummary, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	header, revoked, ok := splitCRLRevokedEntries(data)
	if !ok {
		// Malformed structure, let the standard library produce the error.
		_, err := x509.ParseRevocationList(data)
		if err == nil {
			err = errors.New("x509: malformed crl")
		}

		return crlSummary{}, err
	}

	rl, err := x509.ParseRevocationList(header)
	if err != nil {
		return crlSummary{}, err
	}

	summary := crlSummary{
		issuerCommonName: rl.Issuer.CommonName,
		thisUpdate:       rl.ThisUpdate,
		nextUpdate:       rl.NextUpdate,
	}

	if err := countCRLRevokedEntries(revoked, &summary); err != nil {
		return crlSummary{}, err
	}

	return summary, nil
}

// Splits a DER encoded CRL into an equivalent CRL without revoked entries and
// the contents of the revokedCertificates sequence.
//
// RFC 5280 Section 5.1:
//
//	CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
//	TBSCertList ::= SEQUENCE { version, signature, issuer, thisUpdate,
//	  nextUpdate OPTIONAL, revokedCertificates OPTIONAL, crlExtensions [0] OPTIONAL }
func splitCRLRevokedEntries(der []byte) ([]byte, cryptobyte.String, bool) {
	input := cryptobyte.String(der)
	var crlSeq, tbs, sigAlg, sigValue cryptobyte.String
	if !input.ReadASN1(&crlSeq, cryptobyte_asn1.SEQUENCE) ||
		!crlSeq.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) ||
		!crlSeq.ReadASN1Element(&sigAlg, cryptobyte_asn1.SEQUENCE) ||
		!crlSeq.ReadASN1Element(&sigValue, cryptobyte_asn1.BIT_STRING) {
		return nil, nil, false
	}

	rest := tbs
	if !rest.SkipASN1(cryptobyte_asn1.INTEGER) || // version
		!rest.SkipASN1(cryptobyte_asn1.SEQUENCE) || // signature
		!rest.SkipASN1(cryptobyte_asn1.SEQUENCE) || // issuer
		!skipCRLTime(&rest) { // thisUpdate
		return nil, nil, false
	}
	if rest.PeekASN1Tag(cryptobyte_asn1.UTCTime) || rest.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime) {
		if !skipCRLTime(&rest) { // nextUpdate
			return nil, nil, false
		}
	}

	revokedStart := len(tbs) - len(rest)
	var revoked cryptobyte.String
	if rest.PeekASN1Tag(cryptobyte_asn1.SEQUENCE) {
		if !rest.ReadASN1(&revoked, cryptobyte_asn1.SEQUENCE) {
			return nil, nil, false
		}
	}
	// Only the crlExtensions element is kept, the standard library ignores any trailing data.
	var extensions cryptobyte.String
	if rest.PeekASN1Tag(crlExtensionsTag) && !rest.ReadASN1Element(&extensions, crlExtensionsTag) {
		return nil, nil, false
	}

	b := cryptobyte.NewBuilder(make([]byte, 0, revokedStart+len(extensions)+len(sigAlg)+len(sigValue)+16))
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(tbs[:revokedStart])
			b.AddBytes(extensions)
		})
		b.AddBytes(sigAlg)
		b.AddBytes(sigValue)
	})
	header, err := b.Bytes()
	if err != nil {
		return nil, nil, false
	}

	return header, revoked, true
}

func skipCRLTime(s *cryptobyte.String) bool {
	if s.PeekASN1Tag(cryptobyte_asn1.UTCTime) {
		return s.SkipASN1(cryptobyte_asn1.UTCTime)
	}

	return s.SkipASN1(cryptobyte_asn1.GeneralizedTime)
}

// Counts revoked entries per reason, validating the entry structure
// the same way as x509.ParseRevocationList apart from revocation date contents.
func countCRLRevokedEntries(revoked cryptobyte.String, summary *crlSummary) error {
	for !revoked.Empty() {
		var entry cryptobyte.String
		if !revoked.ReadASN1(&entry, cryptobyte_asn1.SEQUENCE) {
			return errors.New("x509: malformed crl")
		}

		var serial cryptobyte.String
		if !entry.ReadASN1(&serial, cryptobyte_asn1.INTEGER) || !isValidASN1Integer(serial) {
			return errors.New("x509: malformed serial number")
		}
		if !entry.PeekASN1Tag(cryptobyte_asn1.UTCTime) && !entry.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime) {
			return errors.New("x509: unsupported time format")
		}
		if !skipCRLTime(&entry) {
			return errors.New("x509: malformed revocation time")
		}

		reasonCode, err := readCRLEntryReasonCode(&entry)
		if err != nil {
			return err
		}

		summary.revokedCertificates++
		summary.revokedCertificatesByReason[crlReasonSlot(reasonCode)]++
	}

	return nil
}

// Reads the optional entry extensions and returns the reasonCode value, defaulting to unspecified when absent.
func readCRLEntryReasonCode(entry *cryptobyte.String) (int, error) {
	var extensions cryptobyte.String
	var present bool
	if !entry.ReadOptionalASN1(&extensions, &present, cryptobyte_asn1.SEQUENCE) {
		return 0, errors.New("x509: malformed extensions")
	}

	reasonCode := crlReasonUnspecified
	for present && !extensions.Empty() {
		var extension, oid, value cryptobyte.String
		if !extensions.ReadASN1(&extension, cryptobyte_asn1.SEQUENCE) {
			return 0, errors.New("x509: malformed extension")
		}
		if !extension.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) || len(oid) == 0 {
			return 0, errors.New("x509: malformed extension OID field")
		}
		if extension.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
			var critical bool
			if !extension.ReadASN1Boolean(&critical) {
				return 0, errors.New("x509: malformed extension critical field")
			}
		}
		if !extension.ReadASN1(&value, cryptobyte_asn1.OCTET_STRING) {
			return 0, errors.New("x509: malformed extension value field")
		}
		if bytes.Equal(oid, oidExtensionReasonCodeDER) && !value.ReadASN1Enum(&reasonCode) {
			return 0, errors.New("x509: malformed reasonCode extension")
		}
	}

	return reasonCode, nil
}

// Reports whether bytes are a valid, minimally encoded DER INTEGER.
func isValidASN1Integer(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) == 1 {
		return true
	}

	return (b[0] != 0 || b[1]&0x80 != 0) && (b[0] != 0xff || b[1]&0x80 != 0x80)
}
