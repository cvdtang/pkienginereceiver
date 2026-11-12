package pkienginereceiver

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
)

func TestNewVaultConfigSizesIdleConnectionPool(t *testing.T) {
	t.Parallel()

	cfg := createDefaultConfig().(*config)
	cfg.ConcurrencyLimit = 256

	assert.Equal(t, 256, newVaultConfig(*cfg).HttpClient.Transport.(*http.Transport).MaxIdleConnsPerHost)
}

func TestScraperCRLClientSizesIdleConnectionPool(t *testing.T) {
	t.Parallel()

	scraper, _ := createTestScraperWithConfig(t, func(cfg *config) {
		cfg.ConcurrencyLimit = 32
	})

	assert.Equal(t, 32, scraper.crlClient.Transport.(*http.Transport).MaxIdleConnsPerHost)
}

// Ensures shutdown closes the idle connections of the secret store client.
func TestScraperShutdownClosesIdleConnections(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Token lookup without TTL, so no renewal is started.
		_, _ = w.Write([]byte(`{"data":{"ttl":0}}`))
	}))
	defer server.Close()

	// Captures the connection of the token lookup.
	var conn net.Conn
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { conn = info.Conn },
	})

	cfg := createDefaultConfig().(*config)
	cfg.Address = server.URL
	cfg.Auth.AuthToken.Token = "test-token"
	scraper := newPkiEngineScraper(cfg, receivertest.NewNopSettings(metadata.Type))

	require.NoError(t, scraper.start(ctx, componenttest.NewNopHost()))
	_, err := scraper.ensureSecretStore()
	require.NoError(t, err)
	require.NotNil(t, conn)

	require.NoError(t, scraper.shutdown(ctx))
	require.ErrorIs(t, conn.SetDeadline(time.Time{}), net.ErrClosed)
}
