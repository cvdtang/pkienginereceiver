package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

var _ secretStore = (*vault)(nil)

// Internal pseudo-method for list operations; rawRequest sends it as
// GET with a list=true query parameter.
const httpMethodList = "LIST"

type secretStore interface {
	startTokenRenewal(ctx context.Context, wg *sync.WaitGroup)
	readClusterConfiguration(ctx context.Context, mount string) (*vaultapi.Secret, error)
	listMountPathsTypePki(ctx context.Context) ([]string, error)
	listIssuers(ctx context.Context, mount string) (*vaultapi.Secret, error)
	readIssuer(ctx context.Context, mount string, id string) (*vaultapi.Secret, error)
	listCertificates(ctx context.Context, mount string) (*vaultapi.Secret, error)
	readCertificate(ctx context.Context, mount string, serial string) (*vaultapi.Secret, error)
}

// Performs a Vault API request and returns the parsed secret.
// It preserves the SDK semantics of returning a nil secret without an error for 404 responses.
//
// Rate limited (429) responses are retried after the server-suggested wait so
// the request succeeds or the request timeout expires. The retry loop is stateless:
// it only blocks the request that was rate limited and never paces other requests.
func (v *vault) rawLogical(ctx context.Context, method string, requestPath string) (*vaultapi.Secret, error) {
	// Bound the whole retry loop. Each raw request applies the client-configured
	// timeout to a single call, so an explicit deadline is needed to bound the
	// loop across re-issues.
	ctx, cancel := context.WithTimeout(ctx, v.requestTimeout)
	defer cancel()

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resp, err := v.rawRequest(ctx, method, requestPath)

		// Rate limited: wait the server-specified duration and re-issue.
		// Drain and close the response body before sleeping so the connection
		// can be reused instead of being held open for the wait.
		if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			if sleepCtx(ctx, retryWait(resp.Header)) {
				continue
			}

			return nil, ctx.Err()
		}

		return v.client.Logical().ParseRawResponseAndCloseBody(resp, err)
	}
}

// Issues the raw Vault API request and returns the raw response.
// The SDK still surfaces non-2xx statuses as a ResponseError (err non-nil)
// while leaving the response non-nil, so callers must check resp.StatusCode
// before err. LIST requests are sent as GET with a list=true query parameter,
// as there is no raw list variant in the SDK.
func (v *vault) rawRequest(ctx context.Context, method string, requestPath string) (*vaultapi.Response, error) {
	var params map[string][]string
	if method == httpMethodList {
		params = map[string][]string{"list": {"true"}}
	}

	return v.client.Logical().ReadRawWithDataWithContext(ctx, requestPath, params)
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-cluster-configuration
func (v *vault) readClusterConfiguration(ctx context.Context, mount string) (*vaultapi.Secret, error) {
	requestPath := path.Join(mount, "config/cluster")

	return v.rawLogical(ctx, http.MethodGet, requestPath)
}

// Call secret store to list mounts, only return mounts of type `pki`.
//
// API: https://developer.hashicorp.com/vault/api-docs/system/mounts
func (v *vault) listMountPathsTypePki(ctx context.Context) ([]string, error) {
	secret, err := v.rawLogical(ctx, http.MethodGet, "sys/mounts")
	if err != nil {
		return nil, fmt.Errorf("error listing mounts: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	mounts := map[string]*vaultapi.MountOutput{}
	if err := mapstructure.Decode(secret.Data, &mounts); err != nil {
		return nil, err
	}

	pkiMountPaths := make([]string, 0, len(mounts))
	for path, mount := range mounts {
		if mount.Type != "pki" {
			continue
		}

		pkiMountPaths = append(pkiMountPaths, path)
	}

	slices.Sort(pkiMountPaths)

	return pkiMountPaths, nil
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#list-issuers
func (v *vault) listIssuers(ctx context.Context, mount string) (*vaultapi.Secret, error) {
	requestPath := path.Join(mount, "issuers")

	return v.rawLogical(ctx, httpMethodList, requestPath)
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer
func (v *vault) readIssuer(ctx context.Context, mount string, id string) (*vaultapi.Secret, error) {
	requestPath := path.Join(mount, "issuer", id)

	return v.rawLogical(ctx, http.MethodGet, requestPath)
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#list-certificates
func (v *vault) listCertificates(ctx context.Context, mount string) (*vaultapi.Secret, error) {
	requestPath := path.Join(mount, "certs")

	return v.rawLogical(ctx, httpMethodList, requestPath)
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-certificate
func (v *vault) readCertificate(ctx context.Context, mount string, serial string) (*vaultapi.Secret, error) {
	requestPath := path.Join(mount, "cert", serial)

	return v.rawLogical(ctx, http.MethodGet, requestPath)
}
