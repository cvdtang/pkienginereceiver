package pkienginereceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	validConfig := func() *config {
		return &config{
			Address:    "http://127.0.0.1:8200",
			MatchRegex: ".*",
			Crl: crlConfig{
				CacheSize: 1,
			},
			Auth: authConfig{
				AuthType: authTypeToken,
				AuthToken: authToken{
					Token: "token",
				},
			},
		}
	}

	tests := []struct {
		name          string
		c             *config
		errorExpected string
	}{
		{
			name:          "good config",
			c:             validConfig(),
			errorExpected: "",
		},
		{
			name: "invalid endpoint",
			c: func() *config {
				cfg := validConfig()
				cfg.Address = "127.0.0.1:8200"
				return cfg
			}(),
			errorExpected: "failed parsing address uri:",
		},
		{
			name: "invalid protocol",
			c: func() *config {
				cfg := validConfig()
				cfg.Address = "ftp://127.0.0.1:8200"
				return cfg
			}(),
			errorExpected: "address invalid protocol",
		},
		{
			name: "missing host",
			c: func() *config {
				cfg := validConfig()
				cfg.Address = "http://"
				return cfg
			}(),
			errorExpected: "address no host specified",
		},
		{
			name: "invalid regex",
			c: func() *config {
				cfg := validConfig()
				// backtracking not supported by RE2
				cfg.MatchRegex = "\\1"
				return cfg
			}(),
			errorExpected: "failed compiling regex:",
		},
		{
			name: "unsupported auth type",
			c: func() *config {
				cfg := validConfig()
				cfg.Auth.AuthType = "not implemented"
				return cfg
			}(),
			errorExpected: "got unsupported auth type:",
		},
		{
			name: "negative retry interval",
			c: func() *config {
				cfg := validConfig()
				cfg.Crl.RetryInterval = -1 * time.Second
				return cfg
			}(),
			errorExpected: "crl retry interval must be greater than or equal to 0",
		},
		{
			name: "negative crl timeout",
			c: func() *config {
				cfg := validConfig()
				cfg.Crl.Timeout = -1 * time.Second
				return cfg
			}(),
			errorExpected: "crl timeout must be greater than or equal to 0",
		},
		{
			name: "token missing token",
			c: func() *config {
				cfg := validConfig()
				cfg.Auth.AuthToken.Token = ""
				return cfg
			}(),
			errorExpected: "token auth no token specified",
		},
		{
			name: "approle missing role id",
			c: func() *config {
				cfg := validConfig()
				cfg.Auth.AuthType = authTypeAppRole
				cfg.Auth.AuthAppRole.SecretID = "secret-id"
				return cfg
			}(),
			errorExpected: "approle auth no role id specified",
		},
		{
			name: "approle missing secret id",
			c: func() *config {
				cfg := validConfig()
				cfg.Auth.AuthType = authTypeAppRole
				cfg.Auth.AuthAppRole.RoleID = "role-id"
				return cfg
			}(),
			errorExpected: "approle auth no secret id specified",
		},
		{
			name: "kubernetes missing role",
			c: func() *config {
				cfg := validConfig()
				cfg.Auth.AuthType = authTypeKubernetes
				cfg.Auth.AuthKubernetes.ServiceAccountTokenPath = "/tmp/token"
				return cfg
			}(),
			errorExpected: "kubernetes auth no role specified",
		},
		{
			name: "kubernetes missing token and path",
			c: func() *config {
				cfg := validConfig()
				cfg.Auth.AuthType = authTypeKubernetes
				cfg.Auth.AuthKubernetes.RoleName = "role"
				return cfg
			}(),
			errorExpected: "kubernetes auth no service account token or path specified",
		},
		{
			name: "jwt missing role",
			c: func() *config {
				cfg := validConfig()
				cfg.Auth.AuthType = authTypeJWT
				cfg.Auth.AuthJWT.Token = "jwt-token"
				return cfg
			}(),
			errorExpected: "jwt auth no role specified",
		},
		{
			name: "jwt missing token",
			c: func() *config {
				cfg := validConfig()
				cfg.Auth.AuthType = authTypeJWT
				cfg.Auth.AuthJWT.RoleName = "role"
				return cfg
			}(),
			errorExpected: "jwt auth no token or path specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.c.validate()
			if tt.errorExpected == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.errorExpected)
			}
		})
	}
}
