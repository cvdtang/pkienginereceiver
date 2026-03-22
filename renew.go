package pkienginereceiver

import (
	"context"
	"fmt"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// Start goroutine to (re)start secret store leases.
func (v *vault) manageTokenLifecycle(ctx context.Context, authTokenWatcher *vaultapi.LifetimeWatcher) {
	go authTokenWatcher.Start()
	defer authTokenWatcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-authTokenWatcher.DoneCh():
			v.logger.Debug("token failed to renew (e.g. expired or revoked), re-auth required")
			return
		case renewalInfo := <-authTokenWatcher.RenewCh():
			if renewalInfo.Secret.Auth != nil {
				v.logger.Debug("token successfully renewed",
					zap.Duration("leaseDuration", time.Duration(renewalInfo.Secret.Auth.LeaseDuration)*time.Second))
			}
		}
	}
}

// Renews the token lease and re-authenticates on expiry.
func (v *vault) keepRenewingTokenLease(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		authTokenWatcher, err := v.client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
			Secret: v.token,
		})
		if err != nil {
			return fmt.Errorf("error initializing auth token lifetime watcher: %w", err)
		}

		// Blocks until the token expires or the context is cancelled.
		v.manageTokenLifecycle(ctx, authTokenWatcher)

		// When reached, the token expired or failed renewal. Re-auth to get a new one.
		v.logger.Info("token lease expired; attempting re-authentication")
		newAuthToken, err := getAuthToken(ctx, &v.auth, v.client)
		if err != nil {
			v.logger.Error("failed to re-authenticate", zap.Error(err))
			// Wait a few seconds before retrying re-auth to avoid hammering the server.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				continue
			}
		}

		v.token = newAuthToken
	}
}

// Authenticates with the configured method and returns the token secret.
func getAuthToken(ctx context.Context, authCfg *authConfig, client *vaultapi.Client) (*vaultapi.Secret, error) {
	am, err := authCfg.authMethod()
	if err != nil {
		return nil, err
	}

	return am.authenticate(ctx, client)
}

// Runs the background token renewal flow until cancellation.
func (v *vault) startTokenRenewal(renewCtx context.Context, renewWg *sync.WaitGroup) {
	defer renewWg.Done()

	if err := v.keepRenewingTokenLease(renewCtx); err != nil {
		if err != context.Canceled {
			v.logger.Error("token renewal stopped unexpectedly", zap.Error(err))
		}
	}
}
