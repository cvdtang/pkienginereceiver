package pkienginereceiver

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"go.opentelemetry.io/collector/scraper/scraperhelper"
)

type config struct {
	scraperhelper.ControllerConfig `mapstructure:",squash"`
	metadata.MetricsBuilderConfig  `mapstructure:",squash"`
	Address                        string     `mapstructure:"address"`
	Namespace                      string     `mapstructure:"namespace"`
	MatchRegex                     string     `mapstructure:"match_regex"`
	ConcurrencyLimit               uint       `mapstructure:"concurrency_limit"`
	Crl                            crlConfig  `mapstructure:"crl"`
	Auth                           authConfig `mapstructure:"auth"`

	compiledRegex *regexp.Regexp
}

type crlConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	ScrapeParent  bool          `mapstructure:"scrape_parent"`
	CacheSize     uint          `mapstructure:"cache_size"`
	Timeout       time.Duration `mapstructure:"timeout"`
	Retries       uint          `mapstructure:"retries"`
	RetryInterval time.Duration `mapstructure:"retry_interval"`
}

func (c *config) validate() error {

	u, err := url.ParseRequestURI(c.Address)

	if err != nil {
		return fmt.Errorf("failed parsing address uri: %w", err)
	}

	if !slices.Contains([]string{"http", "https"}, u.Scheme) {
		return fmt.Errorf("address invalid protocol")
	}

	if u.Host == "" {
		return fmt.Errorf("address no host specified")
	}

	re, err := regexp.Compile(c.MatchRegex)
	if err != nil {
		return fmt.Errorf("failed compiling regex: %w", err)
	}
	c.compiledRegex = re

	if !slices.Contains(c.Auth.supportedMethods(), c.Auth.AuthType) {
		return fmt.Errorf("got unsupported auth type: '%s'", c.Auth.AuthType)
	}

	switch c.Auth.AuthType {
	case authTypeToken:
		if c.Auth.AuthToken.Token == "" {
			return fmt.Errorf("token auth no token specified")
		}
	case authTypeAppRole:
		if c.Auth.AuthAppRole.RoleID == "" {
			return fmt.Errorf("approle auth no role id specified")
		}
		if c.Auth.AuthAppRole.SecretID == "" {
			return fmt.Errorf("approle auth no secret id specified")
		}
	case authTypeKubernetes:
		if c.Auth.AuthKubernetes.RoleName == "" {
			return fmt.Errorf("kubernetes auth no role specified")
		}
		if c.Auth.AuthKubernetes.ServiceAccountToken == "" && c.Auth.AuthKubernetes.ServiceAccountTokenPath == "" {
			return fmt.Errorf("kubernetes auth no service account token or path specified")
		}
	case authTypeJWT:
		if c.Auth.AuthJWT.RoleName == "" {
			return fmt.Errorf("jwt auth no role specified")
		}
		if c.Auth.AuthJWT.Token == "" && c.Auth.AuthJWT.TokenPath == "" {
			return fmt.Errorf("jwt auth no token or path specified")
		}
	}

	if c.Crl.RetryInterval < 0 {
		return fmt.Errorf("crl retry interval must be greater than or equal to 0")
	}
	if c.Crl.Timeout < 0 {
		return fmt.Errorf("crl timeout must be greater than or equal to 0")
	}

	return nil
}
