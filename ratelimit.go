package pkienginereceiver

import (
	"context"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	rateLimitHeaderRetryAfter = "Retry-After"

	// The minimum wait before re-issuing a rate limited request.
	// The server's Retry-After is honored but never below this floor.
	rateLimitWaitFloor = time.Second

	// Bounds the jitter added to the wait so that
	// blocked workers don't wake in a thundering herd at the same reset time.
	rateLimitWaitJitterMax = 500 * time.Millisecond
)

// Extracts the server-suggested wait before the request is retried from the
// Retry-After header. Returns 0 when the header is absent or invalid.
func retryAfterFromHeaders(header http.Header) time.Duration {
	if v := header.Get(rateLimitHeaderRetryAfter); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}

	return 0
}

// Computes how long to wait before re-issuing a rate limited request:
// the server-suggested duration floored at one second, plus jitter to
// spread concurrent waiters across the reset boundary.
func retryWait(header http.Header) time.Duration {
	wait := max(retryAfterFromHeaders(header), rateLimitWaitFloor)

	//nolint:gosec // Jitter only spreads wake-up timing; cryptographic randomness is not needed.
	return wait + time.Duration(rand.Int64N(int64(rateLimitWaitJitterMax)+1))
}

// Sleeps for the given duration, honoring context cancellation.
// It returns true when the full duration elapsed and false when the context is done.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type rateLimitScrapeCtxKey struct{}

// Attaches the throttled counter to the context, unless one is already present.
func withRateLimitCounter(ctx context.Context, counter *atomic.Int64) context.Context {
	if rateLimitCounterFromContext(ctx) != nil {
		return ctx
	}

	return context.WithValue(ctx, rateLimitScrapeCtxKey{}, counter)
}

func rateLimitCounterFromContext(ctx context.Context) *atomic.Int64 {
	if counter, ok := ctx.Value(rateLimitScrapeCtxKey{}).(*atomic.Int64); ok {
		return counter
	}

	return nil
}

// Holds the per-scrape rate limit observations.
// It is replaced at the start of each scrape and never shared across scrapes.
// Throttling is handled by the blocking retry loop in vault.rawLogical;
// the counter is incremented by the SDK CheckRetry hook for every 429 response the
// scraper receives, including ones the SDK retries internally.
type rateObserver struct {
	throttled atomic.Int64
}

func newRateObserver() *rateObserver {
	return &rateObserver{}
}
