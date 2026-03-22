package pkienginereceiver

import (
	"context"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

type vault struct {
	logger *zap.Logger
	auth   authConfig

	token  *vaultapi.Secret
	client *vaultapi.Client
}

// Creates a Vault client and performs initial authentication.
func newVault(ctx context.Context, cfg config, logger *zap.Logger) (*vault, error) {
	config := vaultapi.DefaultConfig()
	config.Address = cfg.Address

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}

	// Explicitly clear the token possibly set via VAULT_TOKEN.
	client.SetToken("")

	client.SetNamespace(cfg.Namespace)

	authToken, err := getAuthToken(ctx, &cfg.Auth, client)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth token from secret store: %v", err)
	}

	vault := &vault{
		logger: logger,
		auth:   cfg.Auth,
		token:  authToken,
		client: client,
	}

	return vault, nil
}
