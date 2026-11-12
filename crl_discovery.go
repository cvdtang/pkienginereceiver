package pkienginereceiver

import (
	"strings"

	"github.com/hashicorp/vault/sdk/helper/certutil"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

// CRL distribution points of an issuer URL configuration.
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

	tasks := appendCRLTasks(nil, subject.base, metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase)
	tasks = appendCRLTasks(tasks, subject.delta, metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindDelta)

	if !cfg.ScrapeParent {
		return tasks, nil
	}

	tasks = appendCRLTasks(tasks, crt.cert.CRLDistributionPoints, metadata.AttributeCrlRoleIssuer, metadata.AttributeCrlKindBase)

	delta, err := certutil.ParseDeltaCRLExtension(crt.cert)
	if err != nil {
		return tasks, err
	}

	return appendCRLTasks(tasks, delta, metadata.AttributeCrlRoleIssuer, metadata.AttributeCrlKindDelta), nil
}

// Appends a CRL task per URI.
func appendCRLTasks(tasks []crlTask, uris []string, role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) []crlTask {
	for _, uri := range uris {
		tasks = append(tasks, crlTask{uri: uri, role: role, kind: kind})
	}

	return tasks
}
