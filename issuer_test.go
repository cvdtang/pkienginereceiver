package pkienginereceiver

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
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

			got := renderAiaUrlTemplate(tt.url, tt.issuerId, tt.clusterConfig)
			assert.Equal(t, tt.want, got)
		})
	}
}

func createTestIssuer(t *testing.T, secretStore secretStore) issuer {
	t.Helper()

	mountPath := "pki/"
	issuerId := "1ae8ce9d-2f70-0761-a465-8c9840a247a2"

	mount := newIssuer(
		zap.NewNop(),
		secretStore,
		createDefaultConfig().(*config).Crl,
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

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&issuerData{Certificate: ""}, nil)

	_, err := issuer.collect(t.Context())
	assert.ErrorContains(t, err, errMsg)
}

func TestIssuerProcessCertificateProcessError(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	issuer := createTestIssuer(t, mockSecretStore)

	errMsg := "failed processing certificate"

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&issuerData{Certificate: "junk"}, nil)

	_, err := issuer.collect(t.Context())
	assert.ErrorContains(t, err, errMsg)
}

func TestIssuerProcessSkipCopiedIssuer(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	issuer := createTestIssuer(t, mockSecretStore)
	_, certPEM := getTestCertData(t, "example.org CA")

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&issuerData{Certificate: string(certPEM), KeyID: json.RawMessage(`""`)}, nil)

	result, err := issuer.collect(ctx)
	require.NoError(t, err)
	assert.True(t, result.isParent)
}

func TestIssuerProcessSkipCopiedIssuerNilKeyID(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	issuer := createTestIssuer(t, mockSecretStore)
	_, certPEM := getTestCertData(t, "example.org CA")

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&issuerData{Certificate: string(certPEM), KeyID: json.RawMessage("null")}, nil)

	result, err := issuer.collect(ctx)
	require.NoError(t, err)
	assert.True(t, result.isParent)
}

func TestIssuerProcessMissingKeyIDNotSkipped(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	issuer := createTestIssuer(t, mockSecretStore)
	_, certPEM := getTestCertData(t, "example.org CA")

	mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&issuerData{Certificate: string(certPEM)}, nil)

	result, err := issuer.collect(ctx)
	require.NoError(t, err)
	assert.False(t, result.isParent)
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
			issuer.crlConfig.Enabled = tt.crlEnabled

			mockSecretStore.On("readIssuer", ctx, issuer.mountPath, issuer.id).Return(&issuerData{Certificate: string(certPEM), CRLDistributionPoints: []string{"https://subject.example/crl"}, DeltaCRLDistributionPoints: []string{"https://subject.example/crl/delta"}}, nil)

			result, err := issuer.collect(ctx)
			require.NoError(t, err)
			assert.False(t, result.isParent)
			assert.ElementsMatch(t, tt.want, result.crlTasks)
		})
	}
}

func TestIssuerBuildCRLTasksScrapeParent(t *testing.T) {
	t.Parallel()

	parentCrlUri := "https://parent.example/crl"
	data := &issuerData{
		CRLDistributionPoints:      []string{"https://subject.example/crl"},
		DeltaCRLDistributionPoints: []string{"https://subject.example/crl/delta"},
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

			issuer := issuer{
				crlConfig: crlConfig{Enabled: true, ScrapeParent: tt.scrapeParent},
				id:        "issuer-id",
			}

			_, certPEM := getTestCertData(t, "example.org CA", parentCrlUri)
			cert, err := newCertificate(string(certPEM))
			require.NoError(t, err)

			tasks := issuer.buildCRLTasks(data, cert, zap.NewNop())

			require.Len(t, tasks, len(tt.want))
			assert.ElementsMatch(t, tt.want, tasks)
		})
	}
}
