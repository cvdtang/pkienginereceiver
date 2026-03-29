package pkienginereceiver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		serverResponse string
		serverStatus   int
		expectData     []byte
		expectFetch    int64
		expectErr      bool
	}{
		{
			name:           "Success - Valid CRL Fetch",
			serverResponse: "crl-data-payload",
			serverStatus:   http.StatusOK,
			expectData:     []byte("crl-data-payload"),
			expectFetch:    1,
			expectErr:      false,
		},
		{
			name:           "Failure - 404 Not Found",
			serverResponse: "not found",
			serverStatus:   http.StatusNotFound,
			expectData:     nil,
			expectFetch:    0,
			expectErr:      true,
		},
		{
			name:           "Failure - 500 Internal Server Error",
			serverResponse: "server error",
			serverStatus:   http.StatusInternalServerError,
			expectData:     nil,
			expectFetch:    0,
			expectErr:      true,
		},
	}

	ctx := t.Context()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverResponse))
			}))
			defer server.Close()

			fetcher := &realCrlFetcher{client: http.DefaultClient}
			res, err := fetcher.fetchHTTP(ctx, server.URL, time.Second, "", time.Time{})

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectFetch, res.Fetchable)
				assert.Equal(t, tt.expectData, res.Data)
			}
		})
	}
}

func TestFetchHTTP_ConnectionClosed(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection and close it immediately to simulate a network failure
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer server.Close()

	fetcher := &realCrlFetcher{client: http.DefaultClient}
	_, err := fetcher.fetchHTTP(t.Context(), server.URL, time.Second, "", time.Time{})

	assert.ErrorContains(t, err, "EOF", "expected error due to closed connection")
}

func TestFetchHTTP_Headers(t *testing.T) {
	t.Parallel()

	expectedETag := "test-etag"
	expectedLastModified := time.Now().Truncate(time.Second).UTC()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectedETag, r.Header.Get("If-None-Match"))
		assert.Equal(t, expectedLastModified.Format(http.TimeFormat), r.Header.Get("If-Modified-Since"))
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	fetcher := &realCrlFetcher{client: http.DefaultClient}
	res, err := fetcher.fetchHTTP(t.Context(), server.URL, 10*time.Second, expectedETag, expectedLastModified)

	require.ErrorIs(t, err, errNotModified)
	assert.Equal(t, res.Fetchable, int64(1))
}

func TestFetchHTTP_Headers_NotModifiedResponseMetadata(t *testing.T) {
	t.Parallel()

	expectedETag := `"new-etag"`
	expectedLastModified := time.Date(2025, 1, 7, 1, 0, 0, 0, time.UTC)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", expectedETag)
		w.Header().Set("Last-Modified", expectedLastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	fetcher := &realCrlFetcher{client: http.DefaultClient}
	res, err := fetcher.fetchHTTP(t.Context(), server.URL, 10*time.Second, `"old-etag"`, time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC))

	require.ErrorIs(t, err, errNotModified)
	assert.Equal(t, int64(1), res.Fetchable)
	assert.Equal(t, expectedETag, res.ETag)
	assert.True(t, res.LastModified.Equal(expectedLastModified), "304 metadata should be captured for cache updates")
}

func TestFetchHTTP_Headers_WithoutKnownLastModified(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("If-Modified-Since"))
		assert.Empty(t, r.Header.Get("If-None-Match"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	}))
	defer server.Close()

	fetcher := &realCrlFetcher{client: http.DefaultClient}
	res, err := fetcher.fetchHTTP(t.Context(), server.URL, 10*time.Second, "", time.Time{})

	require.NoError(t, err)
	assert.Equal(t, int64(1), res.Fetchable)
}

func TestFetchHTTP_ResponseMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		expectedETag         string
		expectedLastModified time.Time
		writeHeaders         func(w http.ResponseWriter)
		assertMsg            string
	}{
		{
			name:                 "ETag and Last-Modified",
			expectedETag:         "new-etag",
			expectedLastModified: time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC),
			writeHeaders: func(w http.ResponseWriter) {
				w.Header().Set("ETag", "new-etag")
				w.Header().Set("Last-Modified", time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC).Format(http.TimeFormat))
			},
			assertMsg: "LastModified should match",
		},
		{
			name:                 "ETag and Date fallback",
			expectedETag:         "etag-only",
			expectedLastModified: time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC),
			writeHeaders: func(w http.ResponseWriter) {
				w.Header().Set("ETag", "etag-only")
				w.Header().Set("Date", time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC).Format(http.TimeFormat))
			},
			assertMsg: "LastModified should fallback to Date",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.writeHeaders(w)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("data"))
			}))
			defer server.Close()

			fetcher := &realCrlFetcher{client: http.DefaultClient}
			res, err := fetcher.fetchHTTP(t.Context(), server.URL, 10*time.Second, "", time.Time{})

			require.NoError(t, err)
			assert.Equal(t, tt.expectedETag, res.ETag)
			assert.True(t, res.LastModified.Equal(tt.expectedLastModified), tt.assertMsg)
		})
	}
}

func TestFetchHTTP_ResponseMetadata_LastModifiedOnly(t *testing.T) {
	t.Parallel()

	expectedLastModified := time.Date(2025, 1, 1, 1, 0, 0, 0, time.UTC)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", expectedLastModified.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	}))
	defer server.Close()

	fetcher := &realCrlFetcher{client: http.DefaultClient}
	res, err := fetcher.fetchHTTP(t.Context(), server.URL, 10*time.Second, "", time.Time{})

	require.NoError(t, err)
	assert.Empty(t, res.ETag, "ETag should be empty when missing")
	assert.True(t, res.LastModified.Equal(expectedLastModified), "LastModified should match")
}

func TestFetchHTTP_Timeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Longer than timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fetcher := &realCrlFetcher{client: http.DefaultClient}
	// Timeout 0 -> context timeout 0 -> immediate
	_, err := fetcher.fetchHTTP(t.Context(), server.URL, 0, "", time.Time{})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func TestFetchHTTP_MalformedLastModified(t *testing.T) {
	t.Parallel()

	expectedDate := time.Date(2025, 1, 2, 1, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "invalid-date")
		w.Header().Set("Date", expectedDate.Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	}))
	defer server.Close()

	fetcher := &realCrlFetcher{client: http.DefaultClient}
	res, err := fetcher.fetchHTTP(t.Context(), server.URL, 10*time.Second, "", time.Time{})

	require.NoError(t, err)
	assert.True(t, res.LastModified.Equal(expectedDate), "Should fallback to Date if Last-Modified is malformed")
}

func TestFetchHTTP_MissingValidators(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = nil // suppress default Date injection
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	}))
	defer server.Close()

	fetcher := &realCrlFetcher{client: http.DefaultClient}
	res, err := fetcher.fetchHTTP(t.Context(), server.URL, 10*time.Second, "", time.Time{})

	require.NoError(t, err)
	assert.True(t, res.LastModified.IsZero(), "Should remain zero without Last-Modified and Date")
}
