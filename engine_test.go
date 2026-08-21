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
func ctxWithRateObserver(t *testing.T) (context.Context, *rateObserver) {
	t.Helper()

	observer := newRateObserver()

	return withRateLimitCounter(t.Context(), &observer.throttled), observer
}

func vaultJSONResponse(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
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
	secret, err := v.readClusterConfiguration(ctx, "pki/")
	require.NoError(t, err)
	require.NotNil(t, secret)
	assert.Equal(t, "http://example.com/v1/pki", secret.Data["path"])
	assert.Equal(t, "http://example.com/v1/pki", secret.Data["aia_path"])
	assert.Equal(t, int64(0), observer.throttled.Load())
}

// Ensures a 404 response yields a nil secret without an error, preserving Vault SDK semantics.
func TestVaultReadNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		vaultJSONResponse(w, `{"errors":["unsupported path"]}`)
	}))
	defer server.Close()

	v := newTestVault(t, server.URL)
	secret, err := v.readIssuer(t.Context(), "pki/", "missing")
	require.NoError(t, err)
	assert.Nil(t, secret)
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
	secret, err := v.listIssuers(t.Context(), "pki/")
	require.NoError(t, err)
	require.NotNil(t, secret)
	assert.Equal(t, []any{"issuer-1", "issuer-2"}, secret.Data["keys"])
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
	assert.Equal(t, int64(0), observer.throttled.Load())
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
	secret, err := v.readClusterConfiguration(ctx, "pki/")
	require.NoError(t, err)
	require.NotNil(t, secret)

	// The loop waits the one-second floor plus jitter before retrying.
	assert.GreaterOrEqual(t, time.Since(start), time.Second)
	assert.Less(t, time.Since(start), 3*time.Second)

	assert.Equal(t, int64(1), observer.throttled.Load())
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

	assert.Equal(t, int64(1), observer.throttled.Load())
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

	secret, err := v.readClusterConfiguration(ctx, "pki/")
	require.NoError(t, err)
	require.NotNil(t, secret)
	assert.Equal(t, int64(2), observer.throttled.Load())
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
	secret, err := v.readClusterConfiguration(ctx, "pki/")
	require.NoError(t, err)
	require.NotNil(t, secret)
	assert.Equal(t, int64(1), observer.throttled.Load())

	events := transport.eventsSnapshot()
	require.GreaterOrEqual(t, len(events), 3)
	assert.Equal(t, "req:/v1/pki/config/cluster", events[0])
	assert.Equal(t, "close:429:/v1/pki/config/cluster", events[1])
	assert.Equal(t, "req:/v1/pki/config/cluster", events[2])
}
