package pkienginereceiver

import (
	"fmt"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
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

	assert.NoError(t, err)
	assert.Empty(t, result.issuerIDs)
	assert.Equal(t, result.metrics.storedCertificates, &expectedStoredCertificates)
}
