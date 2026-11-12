package pkienginereceiver

import (
	"crypto/x509"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/certutil"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

// CRL distribution points of an issuer or mount-wide URL configuration.
type crlURLs struct {
	base  []string
	delta []string
	// Whether the URLs contain AIA placeholders to resolve per issuer.
	templating bool
}

// Resolves the AIA placeholders for an issuer.
func (u crlURLs) resolve(issuerID string, cluster clusterConfig) crlURLs {
	if !u.templating {
		return u
	}

	resolveAll := func(uris []string) []string {
		resolved := make([]string, len(uris))
		for i, uri := range uris {
			resolved[i] = renderAiaUrlTemplate(uri, issuerID, cluster)
		}

		return resolved
	}

	return crlURLs{base: resolveAll(u.base), delta: resolveAll(u.delta)}
}

// Resolves supported AIA placeholders in an URI template.
func renderAiaUrlTemplate(url string, issuerID string, clusterConfig clusterConfig) string {
	if !strings.Contains(url, "{{") {
		return url
	}

	url = strings.ReplaceAll(url, "{{issuer_id}}", issuerID)
	url = strings.ReplaceAll(url, "{{cluster_path}}", clusterConfig.path)
	url = strings.ReplaceAll(url, "{{cluster_aia_path}}", clusterConfig.aiaPath)

	return url
}

// Builds the CRL tasks of a local issuer from final URLs.
func crlTasks(cfg crlConfig, crt certificate, subject crlURLs) ([]crlTask, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	tasks := subject.tasks(metadata.AttributeCrlRoleSubject)
	if !cfg.ScrapeParent {
		return tasks, nil
	}

	parent, err := certCRLURLs(crt.cert)

	return append(tasks, parent.tasks(metadata.AttributeCrlRoleIssuer)...), err
}

// Reads the CRL distribution points and Freshest CRL extensions of a certificate.
func certCRLURLs(crt *x509.Certificate) (crlURLs, error) {
	delta, err := certutil.ParseDeltaCRLExtension(crt)

	return crlURLs{base: crt.CRLDistributionPoints, delta: delta}, err
}

// Returns a CRL task per URL for the role.
func (u crlURLs) tasks(role metadata.AttributeCrlRole) []crlTask {
	tasks := make([]crlTask, 0, len(u.base)+len(u.delta))
	for _, uri := range u.base {
		tasks = append(tasks, crlTask{uri: uri, role: role, kind: metadata.AttributeCrlKindBase})
	}
	for _, uri := range u.delta {
		tasks = append(tasks, crlTask{uri: uri, role: role, kind: metadata.AttributeCrlKindDelta})
	}

	return tasks
}
