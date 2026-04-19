package pkienginereceiver

import (
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestParseCertificateSecret(t *testing.T) {
	t.Parallel()

	_, certPEM := getTestCertData(t, "leaf.example.org")

	tests := []struct {
		name    string
		secret  *vaultapi.Secret
		wantErr string
	}{
		{
			name: "success",
			secret: &vaultapi.Secret{Data: map[string]any{
				"certificate": string(certPEM),
			}},
		},
		{
			name:    "nil secret",
			secret:  nil,
			wantErr: "certificate not found",
		},
		{
			name:    "invalid certificate attribute",
			secret:  &vaultapi.Secret{Data: map[string]any{"certificate": 1}},
			wantErr: "certificate attribute is empty or invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certSecret, err := parseCertificateSecret(tt.secret)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, certSecret.certificateData)
		})
	}
}

func TestStoredCertCollect(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	storedCert := newStoredCert(zap.NewNop(), mockSecretStore, "pki/", "01:23")
	_, certPEM := getTestCertData(t, "leaf.example.org")

	mockSecretStore.On("readCertificate", ctx, "pki/", "01:23").Return(&vaultapi.Secret{
		Data: map[string]any{
			"certificate": string(certPEM),
		},
	}, nil)

	result, err := storedCert.collect(ctx)
	require.NoError(t, err)
	require.NotNil(t, result.certificate.crt)
	assert.Empty(t, result.certificate.issuerId)
}
