package pkienginereceiver

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.uber.org/zap/zaptest/observer"
)

var integrationMatrixAuthScenarios = []authScenario{
	{
		name: "token",
		configFunc: func(cfg *config, _ *IntegrationSuite, vars tfProjectVars) {
			cfg.Auth.AuthType = "token"
			cfg.Auth.AuthToken.Token = configopaque.String(vars.renewableToken)
		},
	},
	{
		name: "approle",
		configFunc: func(cfg *config, _ *IntegrationSuite, _ tfProjectVars) {
			cfg.Auth.AuthType = "approle"
			cfg.Auth.AuthAppRole.RoleID = "my-role-id"
			cfg.Auth.AuthAppRole.SecretID = configopaque.String("my-secret-id")
		},
	},
	{
		name: "kubernetes_bound_service_account_token",
		configFunc: func(cfg *config, suite *IntegrationSuite, _ tfProjectVars) {
			cfg.Auth.AuthType = "kubernetes"
			cfg.Auth.AuthKubernetes.RoleName = saName
			cfg.Auth.AuthKubernetes.ServiceAccountTokenPath = suite.boundTokenPath
		},
	},
	{
		name: "kubernetes_long_lived_secret_token",
		configFunc: func(cfg *config, suite *IntegrationSuite, _ tfProjectVars) {
			cfg.Auth.AuthType = "kubernetes"
			cfg.Auth.AuthKubernetes.RoleName = saName
			cfg.Auth.AuthKubernetes.ServiceAccountToken = configopaque.String(suite.longLivedServiceAccountToken)
		},
	},
	{
		name: "jwt",
		configFunc: func(cfg *config, suite *IntegrationSuite, _ tfProjectVars) {
			cfg.Auth.AuthType = "jwt"
			cfg.Auth.AuthJWT.RoleName = saName
			cfg.Auth.AuthJWT.TokenPath = suite.boundTokenPath
		},
	},
}

// Auth method matrix. Auth only matters at login: a successful handshake
// yields a token with the pkiengine policy and a full scrape of the standalone
// mount, while a failing one emits no metrics at all. Each cell therefore
// asserts a completed, error-free scrape plus token renewal instead of
// re-asserting a golden file (the scrape output is identical for every method).
func (suite *IntegrationSuite) runAuthMatrix(t *testing.T, ctx context.Context, vars tfProjectVars, secretStoreAddr string) {
	t.Helper()

	for _, auth := range integrationMatrixAuthScenarios {
		t.Run(fmt.Sprintf("auth/namespaced=%t/method=%s", vars.namespaced, auth.name), func(t *testing.T) {
			tc := integrationTestCase{
				name:          auth.name,
				cfgMatchRegex: "^pki/standalone/$",
				tfVars:        vars,
				auth:          auth,
			}

			sink, observedLogs, shutdown := startScraperReceiver(t, ctx, suite, tc, secretStoreAddr, true)
			defer shutdown()

			assertAuthScrapeSucceeds(t, sink, observedLogs)
		})
	}
}

// Verifies a completed, error-free scrape for the configured auth method and
// that the resulting token is being renewed. The standalone mount stores one
// issuer and one leaf certificate.
func assertAuthScrapeSucceeds(t *testing.T, sink *consumertest.MetricsSink, observedLogs *observer.ObservedLogs) {
	t.Helper()

	assert.Eventually(t, func() bool {
		lastMetrics, ok := latestMetricsSnapshot(sink)
		if !ok {
			return false
		}

		return metricValue(lastMetrics, "pkiengine.mount.certificates_stored") == 2 &&
			metricValue(lastMetrics, "pkiengine.issuer.errors") == 0 &&
			metricValue(lastMetrics, "pkiengine.mount.errors") == 0
	}, testScrapeTimeout, testScrapeInterval)

	assert.Eventually(t, func() bool {
		return observedLogs.FilterMessage("token successfully renewed").Len() > 0
	}, testRenewalTimeout, testRenewalInterval)
}
