package pkienginereceiver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestVault(t *testing.T, serverURL string) *vault {
	t.Helper()

	config := vaultapi.DefaultConfig()
	config.Address = serverURL

	client, err := vaultapi.NewClient(config)
	require.NoError(t, err)
	client.SetToken("test-token")
	client.SetMaxRetries(0)
	client.SetCheckRetry(rateLimitCheckRetry)

	return &vault{
		logger:         zap.NewNop(),
		client:         client,
		requestTimeout: 5 * time.Second,
	}
}

// Returns a context carrying a fresh throttled counter,
// mirroring how the scraper attaches the per-scrape counter in scrape().
func ctxWithRateObserver(t *testing.T) (context.Context, *atomic.Int64) {
	t.Helper()

	throttled := new(atomic.Int64)

	return withRateLimitCounter(t.Context(), throttled), throttled
}

func vaultJSONResponse(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

// Ensures listMountPathsTypePki returns only mounts of type pki from the sys/mounts response.
func TestVaultListMountPathsTypePki(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/sys/mounts", r.URL.Path)
		vaultJSONResponse(w, `{"data":{"pki/":{"type":"pki"},"pki-other/":{"type":"pki"},"kv/":{"type":"kv"}}}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	ctx, observer := ctxWithRateObserver(t)
	mounts, err := v.listMountPathsTypePki(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"pki/", "pki-other/"}, mounts)
	assert.Equal(t, int64(0), observer.Load())
}

// Ensures listMountPathsTypePki reports an error when the sys/mounts response carries no data.
func TestVaultListMountPathsTypePkiEmptyData(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultJSONResponse(w, `{}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	_, err := v.listMountPathsTypePki(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "data from server response is empty")
}

// Ensures readClusterConfiguration issues a GET to the pki config/cluster path and parses the cluster config from the response.
func TestVaultReadClusterConfiguration(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/pki/config/cluster", r.URL.Path)

		vaultJSONResponse(w, `{"data":{"path":"http://example.com/v1/pki","aia_path":"http://example.com/v1/pki"}}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	ctx, observer := ctxWithRateObserver(t)
	clusterCfg, err := v.readClusterConfiguration(ctx, "pki/")
	require.NoError(t, err)
	require.NotNil(t, clusterCfg)
	assert.Equal(t, "http://example.com/v1/pki", *clusterCfg.Path)
	assert.Equal(t, "http://example.com/v1/pki", *clusterCfg.AIAPath)
	assert.Equal(t, int64(0), observer.Load())
}

// Ensures readURLConfiguration issues a GET to the pki config/urls path and parses the URL config from the response.
func TestVaultReadURLConfiguration(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/pki/config/urls", r.URL.Path)

		vaultJSONResponse(w, `{"data":{"crl_distribution_points":["http://example.com/v1/pki/crl"],"delta_crl_distribution_points":[],"enable_templating":true}}`)
	}))
	defer server.Close()

	urlCfg, err := newTestVault(t, server.URL).readURLConfiguration(t.Context(), "pki/")
	require.NoError(t, err)
	assert.Equal(t, &urlConfigData{
		CRLDistributionPoints:      []string{"http://example.com/v1/pki/crl"},
		DeltaCRLDistributionPoints: []string{},
		EnableTemplating:           true,
	}, urlCfg)
}

// Ensures listIssuers issues a LIST request with list=true and returns the issuer keys.
func TestVaultListIssuers(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/pki/issuers", r.URL.Path)
		assert.Equal(t, "true", r.URL.Query().Get("list"))
		vaultJSONResponse(w, `{"data":{"keys":["issuer-1","issuer-2"]}}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	issuerIDs, err := v.listIssuers(t.Context(), "pki/")
	require.NoError(t, err)
	require.NotNil(t, issuerIDs)
	assert.Equal(t, []string{"issuer-1", "issuer-2"}, issuerIDs)
}

// Ensures readIssuer decodes all issuer fields.
func TestVaultReadIssuerDecodesFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/pki/issuer/abc", r.URL.Path)
		vaultJSONResponse(w, `{"data":{"certificate":"PEM","key_id":"7b0f","crl_distribution_points":["http://crl"],`+
			`"delta_crl_distribution_points":["http://delta"],"issuing_certificates":["http://ca"],"ocsp_servers":["http://ocsp"],`+
			`"enable_aia_url_templating":true}}`)
	}))
	defer server.Close()

	issuer, err := newTestVault(t, server.URL).readIssuer(t.Context(), "pki/", "abc")
	require.NoError(t, err)
	require.NotNil(t, issuer)
	assert.Equal(t, "PEM", issuer.Certificate)
	assert.JSONEq(t, `"7b0f"`, string(issuer.KeyID))
	assert.Equal(t, []string{"http://crl"}, issuer.CRLDistributionPoints)
	assert.Equal(t, []string{"http://delta"}, issuer.DeltaCRLDistributionPoints)
	assert.Equal(t, []string{"http://ca"}, issuer.IssuingCertificates)
	assert.Equal(t, []string{"http://ocsp"}, issuer.OCSPServers)
	assert.True(t, issuer.EnableAIAURLTemplating)
}

// Ensures a 404 response yields no data without an error, preserving Vault SDK semantics.
func TestVaultReadNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		vaultJSONResponse(w, `{"errors":["unsupported path"]}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	issuer, err := v.readIssuer(t.Context(), "pki/", "missing")
	require.NoError(t, err)
	assert.Nil(t, issuer)
}

// Ensures empty bodies and missing list paths yield no data without an error, preserving SDK semantics.
func TestVaultEmptyAndNotFoundResponses(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pki/cert/empty":
			w.WriteHeader(http.StatusNoContent)
		case "/v1/pki/certs":
			w.WriteHeader(http.StatusNotFound)
			vaultJSONResponse(w, `{"errors":[]}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			vaultJSONResponse(w, `{"errors":["boom"]}`)
		}
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)

	cert, err := v.readCertificate(t.Context(), "pki/", "empty")
	require.NoError(t, err)
	assert.Nil(t, cert)

	serials, err := v.listCertificates(t.Context(), "pki/")
	require.NoError(t, err)
	assert.Empty(t, serials)

	_, err = v.readIssuer(t.Context(), "pki/", "fails")
	require.ErrorContains(t, err, "boom")
}

// Ensures a 429 response is retried after the wait floor and counted once by the rate observer.
func TestVaultRetriesRateLimitedRequest(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			vaultJSONResponse(w, `{"errors":["rate limit quota exceeded"]}`)

			return
		}

		vaultJSONResponse(w, `{"data":{"path":"http://example.com/v1/pki","aia_path":"http://example.com/v1/pki"}}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	ctx, observer := ctxWithRateObserver(t)

	start := time.Now()
	clusterCfg, err := v.readClusterConfiguration(ctx, "pki/")
	require.NoError(t, err)
	require.NotNil(t, clusterCfg)

	// The loop waits the one-second floor plus jitter before retrying.
	assert.GreaterOrEqual(t, time.Since(start), time.Second)
	assert.Less(t, time.Since(start), 3*time.Second)

	assert.Equal(t, int64(1), observer.Load())
}

// Ensures the retry loop stops with DeadlineExceeded when rate limited responses persist past the request timeout.
func TestVaultRateLimitedRequestTimesOut(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		vaultJSONResponse(w, `{"errors":["rate limit quota exceeded"]}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	v.requestTimeout = 300 * time.Millisecond
	ctx, observer := ctxWithRateObserver(t)

	start := time.Now()
	_, err := v.readClusterConfiguration(ctx, "pki/")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.GreaterOrEqual(t, time.Since(start), 300*time.Millisecond)

	assert.Equal(t, int64(1), observer.Load())
}

// Ensures 429 responses the SDK retries internally are all counted by the rate observer, not just the terminal one.
func TestVaultCountsSdkRetriedRateLimits(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			vaultJSONResponse(w, `{"errors":["rate limit quota exceeded"]}`)

			return
		}

		vaultJSONResponse(w, `{"data":{"path":"","aia_path":""}}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	v.client.SetMaxRetries(2)
	ctx, observer := ctxWithRateObserver(t)

	clusterCfg, err := v.readClusterConfiguration(ctx, "pki/")
	require.NoError(t, err)
	require.NotNil(t, clusterCfg)
	assert.Equal(t, int64(2), observer.Load())
}

// Records request order and response body Close() calls to assert the 429
// body is drained and closed before the request is re-issued.
type trackingTransport struct {
	base   http.RoundTripper
	mu     sync.Mutex
	events []string
}

func (t *trackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.record("req:" + req.URL.Path)

	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	status := resp.StatusCode
	resp.Body = &trackingBody{
		ReadCloser: resp.Body,
		closeFn: func() {
			t.record(fmt.Sprintf("close:%d:%s", status, req.URL.Path))
		},
	}

	return resp, nil
}

func (t *trackingTransport) record(event string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, event)
}

func (t *trackingTransport) eventsSnapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return slices.Clone(t.events)
}

type trackingBody struct {
	io.ReadCloser

	closeFn func()
}

func (b *trackingBody) Close() error {
	b.closeFn()

	return b.ReadCloser.Close()
}

// Ensures the 429 response body is closed before the request is re-issued so
// the connection can be reused instead of being held open during the wait.
func TestVaultClosesRateLimitedResponseBodyBeforeRetry(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			vaultJSONResponse(w, `{"errors":["rate limit quota exceeded"]}`)

			return
		}

		vaultJSONResponse(w, `{"data":{"path":"http://example.com/v1/pki","aia_path":"http://example.com/v1/pki"}}`)
	}))
	defer server.Close()

	config := vaultapi.DefaultConfig()
	config.Address = server.URL
	transport := &trackingTransport{base: http.DefaultTransport}
	config.HttpClient = &http.Client{Transport: transport}

	client, err := vaultapi.NewClient(config)
	require.NoError(t, err)
	client.SetToken("test-token")
	client.SetMaxRetries(0)
	client.SetCheckRetry(rateLimitCheckRetry)

	v := &vault{
		logger:         zap.NewNop(),
		client:         client,
		requestTimeout: 5 * time.Second,
	}

	ctx, observer := ctxWithRateObserver(t)
	clusterCfg, err := v.readClusterConfiguration(ctx, "pki/")
	require.NoError(t, err)
	require.NotNil(t, clusterCfg)
	assert.Equal(t, int64(1), observer.Load())

	events := transport.eventsSnapshot()
	require.GreaterOrEqual(t, len(events), 3)
	assert.Equal(t, "req:/v1/pki/config/cluster", events[0])
	assert.Equal(t, "close:429:/v1/pki/config/cluster", events[1])
	assert.Equal(t, "req:/v1/pki/config/cluster", events[2])
}
