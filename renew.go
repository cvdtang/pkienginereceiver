package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v7"
	vaultapi "github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

const (
	reauthBackoffInitial = 5 * time.Second
	reauthBackoffMax     = 2 * time.Minute
)

// Start goroutine to (re)start secret store leases.
// Reports whether the token was renewed at least once.
func (v *vault) manageTokenLifecycle(ctx context.Context, authTokenWatcher *vaultapi.LifetimeWatcher) bool {
	go authTokenWatcher.Start()
	defer authTokenWatcher.Stop()

	renewed := false
	for {
		select {
		case <-ctx.Done():
			return renewed
		case err := <-authTokenWatcher.DoneCh():
			// nil: stopped near end of lease (max TTL reached, not renewable,
			// revoked, or renewals kept failing until the grace period).
			// non-nil: the renewal backoff gave up before the grace period.
			if err != nil {
				v.logger.Warn("token renewal failed, re-auth required", zap.Error(err))
			} else {
				v.logger.Debug("token reached end of life, re-auth required")
			}

			return renewed
		case renewalInfo := <-authTokenWatcher.RenewCh():
			renewed = true
			if renewalInfo.Secret.Auth != nil {
				v.logger.Debug("token successfully renewed",
					zap.Duration("leaseDuration", time.Duration(renewalInfo.Secret.Auth.LeaseDuration)*time.Second))
			}
		}
	}
}

// Renews the token lease and re-authenticates on expiry.
func (v *vault) keepRenewingTokenLease(ctx context.Context) error {
	reauthBackoff := &backoff.ExponentialBackOff{
		InitialInterval:     reauthBackoffInitial,
		RandomizationFactor: 0.2,
		Multiplier:          2,
		MaxInterval:         reauthBackoffMax,
	}
	reauthBackoff.Reset()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// A zero TTL means the token never expires (e.g. root token), nothing to renew.
		if v.token.Auth == nil || v.token.Auth.LeaseDuration == 0 {
			v.logger.Debug("token has no ttl, skipping renewal")
			<-ctx.Done()

			return ctx.Err()
		}

		authTokenWatcher, err := v.client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
			Secret:        v.token,
			RenewBehavior: vaultapi.RenewBehaviorIgnoreErrors,
		})
		if err != nil {
			return fmt.Errorf("error initializing auth token lifetime watcher: %w", err)
		}

		// Blocks until the token nears expiry or the context is cancelled.
		start := time.Now()
		lease := time.Duration(v.token.Auth.LeaseDuration) * time.Second
		renewed := v.manageTokenLifecycle(ctx, authTokenWatcher)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Re-auth with a static token only looks up the same dead token again.
		if v.auth.AuthType == authTypeToken {
			return errors.New("static token reached end of life; use a periodic token or a login based auth method")
		}

		// Healthy if the token was renewed or lived a fair share of its lease,
		// otherwise it ended prematurely and re-auth is backed off.
		if renewed || time.Since(start) >= lease/2 {
			reauthBackoff.Reset()
		} else if !sleepCtx(ctx, reauthBackoff.NextBackOff()) {
			return ctx.Err()
		}

		v.logger.Info("token lease nearing expiry; attempting re-authentication")
		if err := v.reauthenticate(ctx, reauthBackoff); err != nil {
			return err
		}
	}
}

// Re-authenticates until it succeeds, backing off between failed attempts.
func (v *vault) reauthenticate(ctx context.Context, reauthBackoff backoff.BackOff) error {
	for {
		newAuthToken, err := getAuthToken(ctx, &v.auth, v.client)
		if err == nil {
			v.token = newAuthToken

			return nil
		}
		v.logger.Error("failed to re-authenticate", zap.Error(err))

		if !sleepCtx(ctx, reauthBackoff.NextBackOff()) {
			return ctx.Err()
		}
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
		if !errors.Is(err, context.Canceled) {
			v.logger.Error("token renewal stopped unexpectedly", zap.Error(err))
		}
	}
}
