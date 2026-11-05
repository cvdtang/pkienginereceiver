package pkienginereceiver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"

	vaultapi "github.com/hashicorp/vault/api"
)

var _ secretStore = (*vault)(nil)

// Internal pseudo-method for list operations; rawRequest sends it as
// GET with a list=true query parameter.
const httpMethodList = "LIST"

type secretStore interface {
	readClusterConfiguration(ctx context.Context, mount string) (*clusterConfigData, error)
	listMountPathsTypePki(ctx context.Context) ([]string, error)
	listIssuers(ctx context.Context, mount string) ([]string, error)
	readIssuer(ctx context.Context, mount string, id string) (*issuerData, error)
	listCertificates(ctx context.Context, mount string) ([]string, error)
	readCertificate(ctx context.Context, mount string, serial string) (*certificateData, error)
}

type clusterConfigData struct {
	Path    *string `json:"path"`
	AIAPath *string `json:"aia_path"`
}

type issuerData struct {
	Certificate                string          `json:"certificate"`
	KeyID                      json.RawMessage `json:"key_id"`
	CRLDistributionPoints      []string        `json:"crl_distribution_points"`
	DeltaCRLDistributionPoints []string        `json:"delta_crl_distribution_points"`
	EnableAIAURLTemplating     bool            `json:"enable_aia_url_templating"`
}

// Reports whether the issuer has no local key, which is the case for parent issuers copied into intermediate mounts of multi-tier setups.
func (d *issuerData) hasNoLocalKey() bool {
	keyID := bytes.TrimSpace(d.KeyID)

	return bytes.Equal(keyID, []byte("null")) || bytes.Equal(keyID, []byte(`""`))
}

type certificateData struct {
	Certificate string `json:"certificate"`
}

type listData struct {
	Keys []string `json:"keys"`
}

type mountData struct {
	Type string `json:"type"`
}

// Performs a Vault API request and decodes the response `data` field into T.
// It returns nil without an error for 404 and empty responses, preserving the SDK semantics.
func vaultRequest[T any](ctx context.Context, v *vault, method string, requestPath string) (*T, error) {
	var response struct {
		Data *T `json:"data"`
	}
	found, err := v.rawLogical(ctx, method, requestPath, func(body io.Reader) error {
		return json.NewDecoder(body).Decode(&response)
	})
	if err != nil || !found {
		return nil, err
	}

	return response.Data, nil
}

// Performs a Vault API request and decodes the response body.
// It reports false without an error for 404 and empty responses.
//
// Rate limited (429) responses are retried after the server-suggested wait so
// the request succeeds or the request timeout expires. The retry loop is stateless:
// it only blocks the request that was rate limited and never paces other requests.
func (v *vault) rawLogical(ctx context.Context, method string, requestPath string, decode func(io.Reader) error) (bool, error) {
	// Bound the whole retry loop. Each raw request applies the client-configured
	// timeout to a single call, so an explicit deadline is needed to bound the
	// loop across re-issues.
	ctx, cancel := context.WithTimeout(ctx, v.requestTimeout)
	defer cancel()

	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		resp, err := v.rawRequest(ctx, method, requestPath)
		if resp == nil {
			return false, err
		}

		// Rate limited: wait the server-specified duration and re-issue.
		// Drain and close the response body before sleeping so the connection
		// can be reused instead of being held open for the wait.
		if resp.StatusCode == http.StatusTooManyRequests {
			drainAndClose(resp.Body)

			if sleepCtx(ctx, retryWait(resp.Header)) {
				continue
			}

			return false, ctx.Err()
		}

		defer drainAndClose(resp.Body)

		if resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		if err := decode(resp.Body); err != nil {
			if errors.Is(err, io.EOF) {
				return false, nil
			}

			return false, err
		}

		return true, nil
	}
}

func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
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
func (v *vault) readClusterConfiguration(ctx context.Context, mount string) (*clusterConfigData, error) {
	return vaultRequest[clusterConfigData](ctx, v, http.MethodGet, path.Join(mount, "config/cluster"))
}

// Call secret store to list mounts, only return mounts of type `pki`.
//
// API: https://developer.hashicorp.com/vault/api-docs/system/mounts
func (v *vault) listMountPathsTypePki(ctx context.Context) ([]string, error) {
	mounts, err := vaultRequest[map[string]mountData](ctx, v, http.MethodGet, "sys/mounts")
	if err != nil {
		return nil, fmt.Errorf("error listing mounts: %w", err)
	}
	if mounts == nil {
		return nil, errors.New("data from server response is empty")
	}

	pkiMountPaths := make([]string, 0, len(*mounts))
	for path, mount := range *mounts {
		if mount.Type != "pki" {
			continue
		}

		pkiMountPaths = append(pkiMountPaths, path)
	}

	slices.Sort(pkiMountPaths)

	return pkiMountPaths, nil
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#list-issuers
func (v *vault) listIssuers(ctx context.Context, mount string) ([]string, error) {
	return v.list(ctx, path.Join(mount, "issuers"))
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-issuer
func (v *vault) readIssuer(ctx context.Context, mount string, id string) (*issuerData, error) {
	return vaultRequest[issuerData](ctx, v, http.MethodGet, path.Join(mount, "issuer", id))
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#list-certificates
func (v *vault) listCertificates(ctx context.Context, mount string) ([]string, error) {
	return v.list(ctx, path.Join(mount, "certs"))
}

// API: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-certificate
func (v *vault) readCertificate(ctx context.Context, mount string, serial string) (*certificateData, error) {
	return vaultRequest[certificateData](ctx, v, http.MethodGet, path.Join(mount, "cert", serial))
}

// Lists keys, returning an empty list when the path does not exist.
func (v *vault) list(ctx context.Context, requestPath string) ([]string, error) {
	keys, err := vaultRequest[listData](ctx, v, httpMethodList, requestPath)
	if err != nil {
		return nil, err
	}
	if keys == nil || keys.Keys == nil {
		return []string{}, nil
	}

	return keys.Keys, nil
}
