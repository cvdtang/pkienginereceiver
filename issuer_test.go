package pkienginereceiver

import (
	"fmt"
	"testing"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
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
			name: "Replace issuer_id only",
			url:  "https://example.com/{{issuer_id}}/crl",
			clusterConfig: clusterConfig{
				path:    "ignore",
				aiaPath: "ignore",
			},
			issuerId: "my-issuer",
			want:     "https://example.com/my-issuer/crl",
		},
		{
			name: "Replace cluster_path and cluster_aia_path",
			url:  "https://{{cluster_path}}.com/{{cluster_aia_path}}",
			clusterConfig: clusterConfig{
				path:    "example",
				aiaPath: "v1/crl",
			},
			issuerId: "999",
			want:     "https://example.com/v1/crl",
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
		{
			name: "Empty strings",
			url:  "{{issuer_id}}/{{cluster_path}}",
			clusterConfig: clusterConfig{
				path:    "",
				aiaPath: "",
			},
			issuerId: "",
			want:     "/",
		},
		{
			name: "Malformed curly braces (ignored)",
			url:  "https://example.com/{issuer_id}/{{missing_bracket}",
			clusterConfig: clusterConfig{
				path: "p",
			},
			issuerId: "i",
			want:     "https://example.com/{issuer_id}/{{missing_bracket}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			issuer := &issuer{
				id:            tt.issuerId,
				clusterConfig: tt.clusterConfig,
			}
			got := issuer.renderAiaUrlTemplate(tt.url)
			assert.Equal(t, tt.want, got)
		})
	}
}

func createTestIssuer(t *testing.T, secretStore secretStore) issuer {
	t.Helper()

	state := createTestScrapeState(t)
	mountPath := "pki/"
	issuerId := "1ae8ce9d-2f70-0761-a465-8c9840a247a2"

	mount := newIssuer(
		zap.NewNop(),
		secretStore,
		state,
		mountPath,
		issuerId,
		clusterConfig{
			path:    "",
			aiaPath: "",
		},
	)

	return mount
}

func TestIssuerProcessReadIssuerError(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	mockSecretStore := newMocksecretStore(t)
	issuer := createTestIssuer(t, mockSecretStore)

	errMsg := "read issuer err"

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).
		Return(nil, fmt.Errorf("%s", errMsg))

	_, err := issuer.collect(ctx)

	assert.ErrorContains(t, err, errMsg)
}

func TestIssuerProcessErrorCertificateEmpty(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	issuer := createTestIssuer(t, mockSecretStore)

	errMsg := "certificate attribute is empty"

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"certificate": "",
		},
	}, nil)

	_, err := issuer.collect(t.Context())
	assert.ErrorContains(t, err, errMsg)
}

func TestIssuerProcessCertificateProcessError(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	issuer := createTestIssuer(t, mockSecretStore)

	errMsg := "failed processing certificate"

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"certificate": "junk",
		},
	}, nil)

	_, err := issuer.collect(t.Context())
	assert.ErrorContains(t, err, errMsg)
}

func TestIssuerProcessSkipCopiedIssuer(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	issuer := createTestIssuer(t, mockSecretStore)
	_, certPEM := getTestCertData(t, "example.org CA")

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&vaultapi.Secret{
		Data: map[string]interface{}{
			"certificate": string(certPEM),
			"key_id":      "",
		},
	}, nil)

	result, err := issuer.collect(ctx)
	assert.NoError(t, err)
	assert.True(t, result.skipped)
}

func TestIssuerProcessCRLTasksRespectCRLEnabled(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	_, certPEM := getTestCertData(t, "example.org CA")

	tests := []struct {
		name       string
		crlEnabled bool
		want       []crlTask
	}{
		{
			name:       "disabled",
			crlEnabled: false,
			want:       nil,
		},
		{
			name:       "enabled",
			crlEnabled: true,
			want: []crlTask{
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
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockSecretStore := newMocksecretStore(t)
			issuer := createTestIssuer(t, mockSecretStore)
			issuer.state.crlEnabled = tt.crlEnabled

			mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&vaultapi.Secret{
				Data: map[string]interface{}{
					"certificate":                   string(certPEM),
					"crl_distribution_points":       []interface{}{"https://subject.example/crl"},
					"delta_crl_distribution_points": []interface{}{"https://subject.example/crl/delta"},
				},
			}, nil)

			result, err := issuer.collect(ctx)
			require.NoError(t, err)
			assert.False(t, result.skipped)
			assert.ElementsMatch(t, tt.want, result.crlTasks)
		})
	}
}

func TestIssuerBuildCRLTasksScrapeParent(t *testing.T) {
	t.Parallel()

	parentCrlUri := "https://parent.example/crl"
	issuerSecret := &vaultapi.Secret{
		Data: map[string]interface{}{
			"crl_distribution_points":       []interface{}{"https://subject.example/crl"},
			"delta_crl_distribution_points": []interface{}{"https://subject.example/crl/delta"},
		},
	}

	tests := []struct {
		name         string
		scrapeParent bool
		want         []crlTask
	}{
		{
			name:         "enabled",
			scrapeParent: true,
			want: []crlTask{
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
				{
					uri:  parentCrlUri,
					role: metadata.AttributeCrlRoleIssuer,
					kind: metadata.AttributeCrlKindBase,
				},
			},
		},
		{
			name:         "disabled",
			scrapeParent: false,
			want: []crlTask{
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
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			state := createTestScrapeState(t)
			state.crlScrapeParent = tt.scrapeParent

			issuer := issuer{
				state: state,
				id:    "issuer-id",
			}

			_, certPEM := getTestCertData(t, "example.org CA", parentCrlUri)
			cert := newCertificate(state, "pki/", issuer.id, string(certPEM))
			require.NoError(t, cert.collect())

			tasks := issuer.buildCRLTasks(issuerSecret, cert, zap.NewNop())

			require.Len(t, tasks, len(tt.want))
			assert.ElementsMatch(t, tt.want, tasks)
		})
	}
}
