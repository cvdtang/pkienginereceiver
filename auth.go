package pkienginereceiver

import (
	"context"
	"fmt"
	"os"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/kubernetes"
	"go.opentelemetry.io/collector/config/configopaque"
)

const (
	authTypeToken      = "token"
	authTypeAppRole    = "approle"
	authTypeKubernetes = "kubernetes"
	authTypeJWT        = "jwt"
)

type authMethod interface {
	// Performs the authentication against the client.
	authenticate(ctx context.Context, client *vaultapi.Client) (*vaultapi.Secret, error)
}

type authConfig struct {
	AuthType       string         `mapstructure:"type"`
	AuthToken      authToken      `mapstructure:"token"`
	AuthAppRole    authAppRole    `mapstructure:"approle"`
	AuthKubernetes authKubernetes `mapstructure:"kubernetes"`
	AuthJWT        authJWT        `mapstructure:"jwt"`
}

func (cfg *authConfig) supportedMethods() []string {
	return []string{authTypeToken, authTypeAppRole, authTypeKubernetes, authTypeJWT}
}

// Returns the configured authentication implementation.
func (cfg *authConfig) authMethod() (authMethod, error) {
	switch cfg.AuthType {
	case authTypeToken:
		return &cfg.AuthToken, nil
	case authTypeAppRole:
		return &cfg.AuthAppRole, nil
	case authTypeKubernetes:
		return &cfg.AuthKubernetes, nil
	case authTypeJWT:
		return &cfg.AuthJWT, nil
	}

	return nil, fmt.Errorf("unsupported auth method")
}

type authToken struct {
	Token configopaque.String `mapstructure:"token"`
}

func (cfg *authToken) authenticate(ctx context.Context, client *vaultapi.Client) (*vaultapi.Secret, error) {
	cfgToken := string(cfg.Token)
	client.SetToken(cfgToken)

	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to lookup token: %w", err)
	}

	auth := &vaultapi.SecretAuth{
		ClientToken: cfgToken,
	}

	if secret != nil && secret.Data != nil {
		if renewable, ok := secret.Data["renewable"].(bool); ok {
			auth.Renewable = renewable
		}
		if ttl, ok := secret.Data["ttl"].(int); ok {
			auth.LeaseDuration = ttl
		}
	}

	return &vaultapi.Secret{Auth: auth}, nil
}

type authAppRole struct {
	RoleID        string              `mapstructure:"role_id"`
	SecretID      configopaque.String `mapstructure:"secret_id"`
	WrappingToken bool                `mapstructure:"wrapping_token"`
	MountPath     string              `mapstructure:"mount_path"`
}

func (cfg *authAppRole) authenticate(ctx context.Context, client *vaultapi.Client) (*vaultapi.Secret, error) {
	secretID := &approle.SecretID{FromString: string(cfg.SecretID)}

	var opts []approle.LoginOption
	if cfg.WrappingToken {
		opts = append(opts, approle.WithWrappingToken())
	}
	if cfg.MountPath != "" {
		opts = append(opts, approle.WithMountPath(cfg.MountPath))
	}

	appRoleAuth, err := approle.NewAppRoleAuth(
		cfg.RoleID,
		secretID,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize approle authentication: %w", err)
	}

	secret, err := client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to log in with approle authentication: %w", err)
	}

	return secret, nil
}

type authKubernetes struct {
	RoleName                string              `mapstructure:"role_name"`
	ServiceAccountToken     configopaque.String `mapstructure:"service_account_token"`
	ServiceAccountTokenPath string              `mapstructure:"service_account_token_path"`
	MountPath               string              `mapstructure:"mount_path"`
}

func (cfg *authKubernetes) authenticate(ctx context.Context, client *vaultapi.Client) (*vaultapi.Secret, error) {
	var opts []kubernetes.LoginOption
	cfgServiceAccountToken := string(cfg.ServiceAccountToken)
	if cfgServiceAccountToken != "" {
		opts = append(opts, kubernetes.WithServiceAccountToken(cfgServiceAccountToken))
	}
	if cfg.ServiceAccountTokenPath != "" {
		opts = append(opts, kubernetes.WithServiceAccountTokenPath(cfg.ServiceAccountTokenPath))
	}
	if cfg.MountPath != "" {
		opts = append(opts, kubernetes.WithMountPath(cfg.MountPath))
	}

	k8sAuth, err := kubernetes.NewKubernetesAuth(
		cfg.RoleName,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize kubernetes authentication: %w", err)
	}

	secret, err := client.Auth().Login(ctx, k8sAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to log in with kubernetes authentication: %w", err)
	}

	return secret, nil
}

type authJWT struct {
	RoleName  string              `mapstructure:"role_name"`
	Token     configopaque.String `mapstructure:"token"`
	TokenPath string              `mapstructure:"token_path"`
	MountPath string              `mapstructure:"mount_path"`
}

func (cfg *authJWT) authenticate(ctx context.Context, client *vaultapi.Client) (*vaultapi.Secret, error) {
	token, err := cfg.jwtToken()
	if err != nil {
		return nil, err
	}

	loginData := map[string]any{
		"role": cfg.RoleName,
		"jwt":  token,
	}

	path := fmt.Sprintf("auth/%s/login", cfg.MountPath)
	secret, err := client.Logical().WriteWithContext(ctx, path, loginData)
	if err != nil {
		return nil, fmt.Errorf("unable to log in with jwt authentication: %w", err)
	}

	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, fmt.Errorf("jwt auth returned empty client token")
	}
	client.SetToken(secret.Auth.ClientToken)

	return secret, nil
}

// Returns the configured JWT token value from config or file.
func (cfg *authJWT) jwtToken() (string, error) {
	cfgToken := string(cfg.Token)
	if cfgToken != "" {
		return cfgToken, nil
	}

	if cfg.TokenPath == "" {
		return "", fmt.Errorf("jwt auth no token specified")
	}

	raw, err := os.ReadFile(cfg.TokenPath)
	if err != nil {
		return "", fmt.Errorf("unable to read jwt token: %w", err)
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("jwt auth token is empty")
	}

	return token, nil
}
