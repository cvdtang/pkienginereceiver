package pkienginereceiver

import (
	"context"
	"fmt"
	"net/http"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

type vault struct {
	logger *zap.Logger
	auth   authConfig

	token  *vaultapi.Secret
	client *vaultapi.Client

	// Deadline applied to the whole rawLogical retry loop so a single logical
	// request cannot exceed the client timeout across multiple re-issues.
	requestTimeout time.Duration
}

// Creates a Vault client and performs initial authentication.
func newVault(ctx context.Context, cfg config, logger *zap.Logger) (*vault, error) {
	config := vaultapi.DefaultConfig()
	config.Address = cfg.Address

	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}

	// Count every 429 response the scraper receives.
	// The counter is carried in the scrape request context
	// so that auth and token renewal requests are not counted.
	// The SDK's internal retry behavior is preserved by delegating to the default retry policy.
	client.SetCheckRetry(rateLimitCheckRetry)

	// Explicitly clear the token possibly set via VAULT_TOKEN.
	client.SetToken("")

	client.SetNamespace(cfg.Namespace)

	authToken, err := getAuthToken(ctx, &cfg.Auth, client)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth token from secret store: %w", err)
	}

	vault := &vault{
		logger:         logger,
		auth:           cfg.Auth,
		token:          authToken,
		client:         client,
		requestTimeout: config.Timeout,
	}

	return vault, nil
}

// Retry policy hook to count every 429 received.
func rateLimitCheckRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		if counter := rateLimitCounterFromContext(ctx); counter != nil {
			counter.Add(1)
		}
	}

	return vaultapi.DefaultRetryPolicy(ctx, resp, err)
}
