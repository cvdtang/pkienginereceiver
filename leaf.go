package pkienginereceiver

import (
	"time"
	"unique"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

// Emit values of a stored leaf certificate.
type leafCert struct {
	serial    string
	issuerCN  unique.Handle[string]
	subjectCN string
	notAfter  int64 // Unix seconds.
	notBefore int64 // Unix seconds.
	subject   certSubjectAttributes
}

func newLeafCert(crt certificate) leafCert {
	return leafCert{
		serial:    crt.serial,
		issuerCN:  unique.Make(crt.issuerCN),
		subjectCN: crt.subjectCN,
		notAfter:  crt.cert.NotAfter.Unix(),
		notBefore: crt.cert.NotBefore.Unix(),
		subject:   crt.subject,
	}
}

// Emits the leaf metrics relative to now.
func (l *leafCert) emit(mb *metadata.MetricsBuilder, now time.Time, mount string) {
	emitCertificate(
		mb,
		certificateMetricsAt(now, time.Unix(l.notAfter, 0), time.Unix(l.notBefore, 0)),
		metadata.AttributeCertTypeLeaf,
		l.issuerCN.Value(),
		l.serial,
		l.subjectCN,
		l.subject,
		mount,
		"",
	)
}
