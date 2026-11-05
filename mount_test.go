package pkienginereceiver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func createTestMount(t *testing.T, secretStore secretStore) mount {
	t.Helper()

	mount := newMount(
		zap.NewNop(),
		secretStore,
		"pki/",
		true,
	)

	return mount
}

func TestMountProcessGetClusterConfigurationErr(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	mount := createTestMount(t, mockSecretStore)

	mockSecretStore.On("readClusterConfiguration", ctx, mount.path).Return(nil, fmt.Errorf("error"))
	mockSecretStore.On("listCertificates", ctx, mount.path).Return([]string{}, nil).Maybe()
	mockSecretStore.On("listIssuers", ctx, mount.path).Return([]string{}, nil).Maybe()

	_, err := mount.collect(ctx)
	assert.Error(t, err)
}

func TestMountProcessListIssuersErr(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	mount := createTestMount(t, mockSecretStore)

	mockSecretStore.On("readClusterConfiguration", ctx, mount.path).Return(newTestClusterConfigData("", ""), nil)

	mockSecretStore.On("listCertificates", ctx, mount.path).Return([]string{"17:67:16:b0:b9:45:58:c0:3a:29:e3:cb:d6:98:33:7a:a6:3b:66:c1"}, nil)

	mockSecretStore.On("listIssuers", ctx, mount.path).Return(nil, fmt.Errorf("error"))

	// A mount whose issuers cannot be listed is a mount error, not a mount without issuers.
	result, err := mount.collect(ctx)

	require.ErrorContains(t, err, "failed listing issuers: error")
	assert.Equal(t, mountResult{}, result)
}

func TestParseClusterConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    *clusterConfigData
		want    clusterConfig
		wantErr string
	}{
		{
			name: "success",
			data: newTestClusterConfigData("prod-cluster", "aia-prod"),
			want: clusterConfig{
				path:    "prod-cluster",
				aiaPath: "aia-prod",
			},
		},
		{
			name:    "nil data",
			data:    nil,
			wantErr: "empty cluster config",
		},
		{
			name:    "missing path",
			data:    &clusterConfigData{AIAPath: new("aia-prod")},
			wantErr: "missing or invalid path in cluster config",
		},
		{
			name:    "missing aia_path",
			data:    &clusterConfigData{Path: new("prod-cluster")},
			wantErr: "missing or invalid aia_path in cluster config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseClusterConfig(tt.data)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
