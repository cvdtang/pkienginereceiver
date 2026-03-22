package pkienginereceiver

import (
	"context"
	"runtime"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/scraper"
	"go.opentelemetry.io/collector/scraper/scraperhelper"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithMetrics(createMetricsReceiver, metadata.MetricsStability),
	)
}

func createDefaultConfig() component.Config {
	scraperConfig := scraperhelper.NewDefaultControllerConfig()
	scraperConfig.CollectionInterval = 5 * time.Minute
	return &config{
		ControllerConfig:     scraperConfig,
		MetricsBuilderConfig: metadata.DefaultMetricsBuilderConfig(),
		Address:              "http://127.0.0.1:8200",
		Namespace:            "",
		MatchRegex:           ".*",
		ConcurrencyLimit:     uint(runtime.GOMAXPROCS(0)),
		Crl: crlConfig{
			Enabled:       true,
			Timeout:       5 * time.Second,
			CacheSize:     50,
			RetryInterval: 3 * time.Second,
			ScrapeParent:  true,
		},
		Auth: authConfig{
			AuthType: "token",
			AuthAppRole: authAppRole{
				MountPath:     "approle",
				WrappingToken: false,
			},
			AuthKubernetes: authKubernetes{
				MountPath: "kubernetes",
			},
			AuthJWT: authJWT{
				MountPath: "jwt",
			},
		},
	}
}

func createMetricsReceiver(_ context.Context, settings receiver.Settings, cfg component.Config, consumer consumer.Metrics) (receiver.Metrics, error) {
	rCfg := cfg.(*config)
	if err := rCfg.validate(); err != nil {
		return nil, err
	}
	pki := newPkiEngineScraper(rCfg, settings)
	s, err := scraper.NewMetrics(
		pki.scrape,
		scraper.WithStart(pki.start),
		scraper.WithShutdown(pki.shutdown),
	)
	if err != nil {
		return nil, err
	}
	opt := scraperhelper.AddMetricsScraper(metadata.Type, s)

	return scraperhelper.NewMetricsController(
		&rCfg.ControllerConfig,
		settings,
		consumer,
		opt,
	)
}
