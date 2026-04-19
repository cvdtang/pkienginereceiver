package pkienginereceiver

import (
	"context"
	"fmt"
	"path"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"
)

var _ secretStore = (*vault)(nil)

type secretStore interface {
	startTokenRenewal(ctx context.Context, wg *sync.WaitGroup)
	readClusterConfiguration(ctx context.Context, mount string) (*vaultapi.Secret, error)
	listMountPathsTypePki(ctx context.Context) ([]string, error)
	listIssuers(ctx context.Context, mount string) (*vaultapi.Secret, error)
	readIssuer(ctx context.Context, mount string, id string) (*vaultapi.Secret, error)
	listCertificates(ctx context.Context, mount string) (*vaultapi.Secret, error)
	readCertificate(ctx context.Context, mount string, serial string) (*vaultapi.Secret, error)
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-cluster-configuration
func (v *vault) readClusterConfiguration(ctx context.Context, mount string) (*vaultapi.Secret, error) {
	path := path.Join(mount, "config/cluster")
	secret, err := v.client.Logical().ReadWithContext(ctx, path)

	return secret, err
}

// Call secret store to list mounts, only return mounts of type `pki`.
//
// API: https://developer.hashicorp.com/vault/api-docs/system/mounts
func (v *vault) listMountPathsTypePki(ctx context.Context) ([]string, error) {
	pkiMountPaths := make([]string, 0)

	sys := v.client.Sys()

	mounts, err := sys.ListMountsWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing mounts: %w", err)
	}

	for path, mount := range mounts {
		if mount.Type != "pki" {
			continue
		}

		pkiMountPaths = append(pkiMountPaths, path)
	}

	return pkiMountPaths, nil
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#list-issuers
func (v *vault) listIssuers(ctx context.Context, mount string) (*vaultapi.Secret, error) {
	path := path.Join(mount, "issuers")
	secret, err := v.client.Logical().ListWithContext(ctx, path)

	return secret, err
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer
func (v *vault) readIssuer(ctx context.Context, mount string, id string) (*vaultapi.Secret, error) {
	path := path.Join(mount, "issuer", id)
	issuer, err := v.client.Logical().ReadWithContext(ctx, path)

	return issuer, err
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#list-certificates
func (v *vault) listCertificates(ctx context.Context, mount string) (*vaultapi.Secret, error) {
	path := path.Join(mount, "certs")
	secret, err := v.client.Logical().ListWithContext(ctx, path)

	return secret, err
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-certificate
func (v *vault) readCertificate(ctx context.Context, mount string, serial string) (*vaultapi.Secret, error) {
	path := path.Join(mount, "cert", serial)
	issuer, err := v.client.Logical().ReadWithContext(ctx, path)

	return issuer, err
}
