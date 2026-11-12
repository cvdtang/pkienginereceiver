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

	crlBase  []unique.Handle[string]
	crlDelta []unique.Handle[string]
}

func newLeafCert(crt certificate, crls crlURLs) leafCert {
	return leafCert{
		serial:    crt.serial,
		issuerCN:  unique.Make(crt.issuerCN),
		subjectCN: crt.subjectCN,
		notAfter:  crt.cert.NotAfter.Unix(),
		notBefore: crt.cert.NotBefore.Unix(),
		subject:   crt.subject,
		crlBase:   internAll(crls.base),
		crlDelta:  internAll(crls.delta),
	}
}

// Returns the subject CRL tasks of the CRL distribution points in the certificate.
func (l *leafCert) crlTasks() []crlTask {
	return crlURLs{base: handleValues(l.crlBase), delta: handleValues(l.crlDelta)}.tasks(metadata.AttributeCrlRoleSubject)
}

func internAll(values []string) []unique.Handle[string] {
	if len(values) == 0 {
		return nil
	}

	handles := make([]unique.Handle[string], len(values))
	for i, value := range values {
		handles[i] = unique.Make(value)
	}

	return handles
}

func handleValues(handles []unique.Handle[string]) []string {
	values := make([]string, len(handles))
	for i, handle := range handles {
		values[i] = handle.Value()
	}

	return values
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
