package pkienginereceiver

import (
	"context"
	"fmt"
	"testing"
)

type integrationScenario struct {
	name          string
	cfgMatchRegex string
}

var integrationMatrixScenarios = []integrationScenario{
	{
		name:          "standalone",
		cfgMatchRegex: "^pki/standalone/$",
	},
	{
		name:          "two-tier",
		cfgMatchRegex: "^pki/ica_0/$",
	},
}

// Golden flight record matrix. The scraped metrics depend only on the scenario
// and the namespaced mode, never on the auth method (auth runs once at login),
// so every cell uses the canonical token auth and asserts the exact normalized
// metric snapshot against the shared golden file.
func (suite *IntegrationSuite) runGoldenMatrix(t *testing.T, ctx context.Context, vars tfProjectVars, secretStoreAddr string) {
	t.Helper()

	for _, scenario := range integrationMatrixScenarios {
		t.Run(fmt.Sprintf("golden/namespaced=%t/scenario=%s", vars.namespaced, scenario.name), func(t *testing.T) {
			expectedFile := fmt.Sprintf("matrix_%s_namespaced-%t.yaml", scenario.name, vars.namespaced)
			tc := integrationTestCase{
				name:          scenario.name,
				expectedFile:  expectedFile,
				cfgMatchRegex: scenario.cfgMatchRegex,
				tfVars:        vars,
				auth:          tokenAuth,
			}

			sink, _, shutdown := startScraperReceiver(t, ctx, suite, tc, secretStoreAddr, true)
			defer shutdown()

			assertScrapeMetrics(t, sink, tc.expectedFile, testScrapeTimeout)
		})
	}
}
