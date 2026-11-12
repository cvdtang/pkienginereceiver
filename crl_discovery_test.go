package pkienginereceiver

import (
	"slices"
	"testing"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderAiaUrlTemplate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		url           string
		clusterConfig clusterConfig
		issuerId      string
		want          string
	}{
		{
			name: "No placeholders present",
			url:  "https://example.com/crl",
			clusterConfig: clusterConfig{
				path:    "prod-cluster",
				aiaPath: "aia-prod",
			},
			issuerId: "12345",
			want:     "https://example.com/crl",
		},
		{
			name: "Replace all placeholders multiple times",
			url:  "{{issuer_id}}:{{cluster_path}}:{{cluster_aia_path}}:{{issuer_id}}",
			clusterConfig: clusterConfig{
				path:    "path",
				aiaPath: "aia",
			},
			issuerId: "id",
			want:     "id:path:aia:id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := renderAiaUrlTemplate(tt.url, tt.issuerId, tt.clusterConfig)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Ensures AIA placeholders are only resolved when templating is enabled.
func TestCRLURLsResolve(t *testing.T) {
	t.Parallel()

	cluster := clusterConfig{path: "https://bao.example/v1/pki"}
	urls := crlURLs{
		base:  []string{"{{cluster_path}}/issuer/{{issuer_id}}/crl"},
		delta: []string{"{{cluster_path}}/issuer/{{issuer_id}}/crl/delta"},
	}

	assert.Equal(t, urls, urls.resolve("issuer-id", cluster), "without templating")

	urls.templating = true
	assert.Equal(t, crlURLs{
		base:  []string{"https://bao.example/v1/pki/issuer/issuer-id/crl"},
		delta: []string{"https://bao.example/v1/pki/issuer/issuer-id/crl/delta"},
	}, urls.resolve("issuer-id", cluster), "with templating")
}

// Ensures subject CRLs come from the issuer's URLs and issuer CRLs from the certificate, only when parent scraping is enabled.
func TestCRLTasks(t *testing.T) {
	t.Parallel()

	parentCrlUri := "https://parent.example/crl"
	_, certPEM := getTestCertData(t, "example.org CA", parentCrlUri)
	cert, err := newCertificate(string(certPEM))
	require.NoError(t, err)

	subject := crlURLs{
		base:  []string{"https://subject.example/crl"},
		delta: []string{"https://subject.example/crl/delta"},
	}
	subjectTasks := []crlTask{
		{
			uri:  "https://subject.example/crl",
			role: metadata.AttributeCrlRoleSubject,
			kind: metadata.AttributeCrlKindBase,
		},
		{
			uri:  "https://subject.example/crl/delta",
			role: metadata.AttributeCrlRoleSubject,
			kind: metadata.AttributeCrlKindDelta,
		},
	}

	tests := []struct {
		name string
		cfg  crlConfig
		want []crlTask
	}{
		{
			name: "crl disabled",
			cfg: crlConfig{
				Enabled:      false,
				ScrapeParent: true,
			},
			want: nil,
		},
		{
			name: "parent scraping disabled",
			cfg:  crlConfig{Enabled: true},
			want: subjectTasks,
		},
		{
			name: "parent scraping enabled",
			cfg: crlConfig{
				Enabled:      true,
				ScrapeParent: true,
			},
			want: append(slices.Clone(subjectTasks), crlTask{
				uri:  parentCrlUri,
				role: metadata.AttributeCrlRoleIssuer,
				kind: metadata.AttributeCrlKindBase,
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tasks, err := crlTasks(tt.cfg, cert, subject)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, tasks)
		})
	}
}
