package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Parses Last-Modified and optionally falls back to Date.
func parseLastModifiedHeader(headers http.Header, allowDateFallback bool) time.Time {
	if lastModified := headers.Get("Last-Modified"); lastModified != "" {
		if t, err := http.ParseTime(lastModified); err == nil {
			return t
		}
	}

	if allowDateFallback {
		if date := headers.Get("Date"); date != "" {
			if t, err := http.ParseTime(date); err == nil {
				return t
			}
		}
	}

	return time.Time{}
}

// Fetches CRL data over HTTP with conditional revalidation headers.
func (f *realCrlFetcher) fetchHTTP(ctx context.Context, uri string, timeout time.Duration, previousETag string, previousLastModified time.Time) (res fetchResult, err error) {
	res.Fetchable = 0

	derivedCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(derivedCtx, http.MethodGet, uri, nil)
	if err != nil {
		return res, newPermanentFetchError(fmt.Errorf("failed to create http request: %w", err))
	}

	if previousETag != "" {
		req.Header.Set("If-None-Match", previousETag)
	}
	if !previousLastModified.IsZero() {
		req.Header.Set("If-Modified-Since", previousLastModified.Format(http.TimeFormat))
	}

	resp, err := f.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return res, err
		}
		return res, newRetryableFetchError(fmt.Errorf("failed to fetch crl: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		res.Fetchable = 1
		res.ETag = resp.Header.Get("ETag")
		res.LastModified = parseLastModifiedHeader(resp.Header, false)
		return res, errNotModified
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected HTTP status: %s", resp.Status)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return res, newPermanentFetchError(err)
		}
		if isRetryableHTTPStatus(resp.StatusCode) {
			return res, newRetryableFetchError(err)
		}
		return res, newPermanentFetchError(err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return res, newRetryableFetchError(fmt.Errorf("failed to read data: %w", err))
	}

	res.Fetchable = 1
	res.Data = data
	res.ETag = resp.Header.Get("ETag")
	res.LastModified = parseLastModifiedHeader(resp.Header, true)

	return res, nil
}

func isRetryableHTTPStatus(statusCode int) bool {
	if statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests {
		return true
	}
	return statusCode >= http.StatusInternalServerError
}
