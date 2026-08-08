package pkienginereceiver

import (
	"fmt"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func createTestMount(t *testing.T, secretStore secretStore) mount {
	t.Helper()

	state := createTestScrapeState(t)
	mountPath := "pki/"

	mount := newMount(
		zap.NewNop(),
		secretStore,
		state,
		mountPath,
	)

	return mount
}

func TestMountProcessGetClusterConfigurationErr(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	mount := createTestMount(t, mockSecretStore)

	mockSecretStore.On("readClusterConfiguration", ctx, mount.path).Return(nil, fmt.Errorf("error"))
	mockSecretStore.On("listCertificates", ctx, mount.path).Return(&vaultapi.Secret{Data: map[string]any{"keys": []any{}}}, nil).Maybe()
	mockSecretStore.On("listIssuers", ctx, mount.path).Return(&vaultapi.Secret{Data: map[string]any{"keys": []any{}}}, nil).Maybe()

	_, err := mount.collect(ctx)
	assert.Error(t, err)
}

func TestMountProcessListIssuersErr(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	mount := createTestMount(t, mockSecretStore)

	mockSecretStore.On("readClusterConfiguration", ctx, mount.path).Return(&vaultapi.Secret{
		Data: map[string]any{
			"path":     "",
			"aia_path": "",
		},
	}, nil)

	mockSecretStore.On("listCertificates", ctx, mount.path).Return(&vaultapi.Secret{
		Data: map[string]any{
			"keys": []any{"17:67:16:b0:b9:45:58:c0:3a:29:e3:cb:d6:98:33:7a:a6:3b:66:c1"},
		},
	}, nil)

	mockSecretStore.On("listIssuers", ctx, mount.path).Return(nil, fmt.Errorf("error"))

	result, err := mount.collect(ctx)

	expectedStoredCertificates := int64(1)

	require.NoError(t, err)
	assert.Empty(t, result.issuerIDs)
	assert.Equal(t, &expectedStoredCertificates, result.metrics.storedCertificates)
}

func TestParseClusterConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		secret  *vaultapi.Secret
		want    clusterConfig
		wantErr string
	}{
		{
			name: "success",
			secret: &vaultapi.Secret{Data: map[string]any{
				"path":     "prod-cluster",
				"aia_path": "aia-prod",
			}},
			want: clusterConfig{
				path:    "prod-cluster",
				aiaPath: "aia-prod",
			},
		},
		{
			name:    "nil secret",
			secret:  nil,
			wantErr: "empty secret or data",
		},
		{
			name:    "nil data",
			secret:  &vaultapi.Secret{},
			wantErr: "empty secret or data",
		},
		{
			name:    "missing path",
			secret:  &vaultapi.Secret{Data: map[string]any{"aia_path": "aia-prod"}},
			wantErr: "missing or invalid path in cluster config",
		},
		{
			name:    "missing aia_path",
			secret:  &vaultapi.Secret{Data: map[string]any{"path": "prod-cluster"}},
			wantErr: "missing or invalid aia_path in cluster config",
		},
		{
			name:    "invalid path type",
			secret:  &vaultapi.Secret{Data: map[string]any{"path": 1, "aia_path": "aia-prod"}},
			wantErr: "missing or invalid path in cluster config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseClusterConfig(tt.secret)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
