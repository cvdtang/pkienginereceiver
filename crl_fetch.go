package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

var errCrlParseUri = errors.New("failed parsing CDP uri")
var errCrlUnsupportedProtocol = errors.New("unsupported protocol")
var errNotModified = errors.New("CRL not modified")

const (
	httpScheme  = "http"
	httpsScheme = "https"
)

type fetchResult struct {
	Fetchable    int64
	Data         []byte
	LastModified time.Time
	ETag         string
}

type crlFetchError struct {
	err       error
	retryable bool
}

func (e *crlFetchError) Error() string {
	return e.err.Error()
}

func (e *crlFetchError) Unwrap() error {
	return e.err
}

func newFetchError(err error, retryable bool) error {
	return &crlFetchError{
		err:       err,
		retryable: retryable,
	}
}

func newRetryableFetchError(err error) error {
	return newFetchError(err, true)
}

func newPermanentFetchError(err error) error {
	return newFetchError(err, false)
}

func isRetryableFetchError(err error) bool {
	var fetchErr *crlFetchError

	return errors.As(err, &fetchErr) && fetchErr.retryable
}

type crlFetcher interface {
	fetch(ctx context.Context, uri string, timeout time.Duration, previousETag string, previousLastModified time.Time) (fetchResult, error)
}

var _ crlFetcher = (*realCrlFetcher)(nil)

type realCrlFetcher struct {
	client *http.Client
}

// Routes CRL fetching to the protocol-specific fetcher.
func (f *realCrlFetcher) fetch(ctx context.Context, uri string, timeout time.Duration, previousETag string, previousLastModified time.Time) (fetchResult, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return fetchResult{}, newPermanentFetchError(fmt.Errorf("%w: %w", errCrlParseUri, err))
	}

	switch u.Scheme {
	case httpScheme, httpsScheme:
		return f.fetchHTTP(ctx, uri, timeout, previousETag, previousLastModified)
	case ldapScheme, ldapsScheme:
		fetchable, data, err := f.fetchLDAP(ctx, &realLdapDialer{}, uri, timeout)

		return fetchResult{
			Fetchable: fetchable,
			Data:      data,
		}, err
	default:
		return fetchResult{}, newPermanentFetchError(fmt.Errorf("%w: %s", errCrlUnsupportedProtocol, u.Scheme))
	}
}
