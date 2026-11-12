package pkienginereceiver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMountProcessListIssuersErr(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(newTestClusterConfigData("", ""), nil)
	mockSecretStore.On("listCertificates", ctx, testMountPath).Return([]string{testCertificateSerialKey}, nil)
	mockSecretStore.On("listIssuers", ctx, testMountPath).Return(nil, fmt.Errorf("error"))

	// A mount whose issuers cannot be listed is a mount error, not a mount without issuers.
	result, err := readMount(ctx, mockSecretStore, testMountPath, true)

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
