package pkienginereceiver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testMountOptions = mountOptions{
	listCertificates: true,
	readURLs:         true,
}

func TestMountProcessListIssuersErr(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	mockSecretStore := newMocksecretStore(t)
	mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(newTestClusterConfigData("", ""), nil)
	mockSecretStore.On("readURLConfiguration", ctx, testMountPath).Return(&urlConfigData{}, nil)
	mockSecretStore.On("listCertificates", ctx, testMountPath).Return([]string{testCertificateSerialKey}, nil)
	mockSecretStore.On("listIssuers", ctx, testMountPath).Return(nil, fmt.Errorf("error"))

	// A mount whose issuers cannot be listed is a mount error, not a mount without issuers.
	result, err := readMount(ctx, mockSecretStore, testMountPath, testMountOptions)

	require.ErrorContains(t, err, "failed listing issuers: error")
	assert.Equal(t, mountResult{}, result)
}

// Ensures the mount-wide CRL distribution points are read and a failed read fails the mount.
func TestReadMountURLConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    *urlConfigData
		err     error
		want    crlURLs
		wantErr string
	}{
		{
			name: "success",
			data: &urlConfigData{
				CRLDistributionPoints:      []string{"https://mount.example/crl"},
				DeltaCRLDistributionPoints: []string{"https://mount.example/crl/delta"},
				EnableTemplating:           true,
			},
			want: crlURLs{
				base:       []string{"https://mount.example/crl"},
				delta:      []string{"https://mount.example/crl/delta"},
				templating: true,
			},
		},
		{
			name:    "read error",
			err:     errTest,
			wantErr: "failed reading url config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			mockSecretStore := newMocksecretStore(t)
			mockSecretStore.On("readClusterConfiguration", ctx, testMountPath).Return(newTestClusterConfigData("", ""), nil)
			mockSecretStore.On("readURLConfiguration", ctx, testMountPath).Return(tt.data, tt.err)
			mockSecretStore.On("listCertificates", ctx, testMountPath).Return([]string{}, nil).Maybe()
			mockSecretStore.On("listIssuers", ctx, testMountPath).Return([]string{}, nil).Maybe()

			result, err := readMount(ctx, mockSecretStore, testMountPath, testMountOptions)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, result.crlURLs)
		})
	}
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
