package pkienginereceiver

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetryAfterFromHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(h http.Header)
		expected time.Duration
	}{
		{
			name: "retry-after parsed",
			setup: func(h http.Header) {
				h.Set("Retry-After", "5")
			},
			expected: 5 * time.Second,
		},
		{
			name: "invalid or unrelated header",
			setup: func(h http.Header) {
				h.Set("Retry-After", "soon")
				h.Set("X-Ratelimit-Reset", "2")
			},
			expected: 0,
		},
		{
			name:     "absent",
			setup:    func(http.Header) {},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			header := http.Header{}
			tt.setup(header)

			assert.Equal(t, tt.expected, retryAfterFromHeaders(header))
		})
	}
}

// Ensures the wait is floored at one second plus jitter when no Retry-After header is present.
func TestRetryWait_FloorsAtOneSecond(t *testing.T) {
	t.Parallel()

	wait := retryWait(http.Header{})
	assert.GreaterOrEqual(t, wait, time.Second)
	assert.LessOrEqual(t, wait, time.Second+rateLimitWaitJitterMax)
}

// Ensures a server-suggested Retry-After duration plus jitter is honored.
func TestRetryWait_HonorsServerSuggestedWait(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	header.Set("Retry-After", "3")

	wait := retryWait(header)
	assert.GreaterOrEqual(t, wait, 3*time.Second)
	assert.LessOrEqual(t, wait, 3*time.Second+rateLimitWaitJitterMax)
}

// Ensures the sleep blocks for the full requested duration when the context stays alive.
func TestSleepCtx_SleepsFullDuration(t *testing.T) {
	t.Parallel()

	start := time.Now()
	require.True(t, sleepCtx(t.Context(), 20*time.Millisecond))
	assert.GreaterOrEqual(t, time.Since(start), 20*time.Millisecond)
}

// Ensures a zero or negative duration returns immediately.
func TestSleepCtx_ZeroDuration(t *testing.T) {
	t.Parallel()

	assert.True(t, sleepCtx(t.Context(), 0))
}

// Ensures the sleep returns false when the context is cancelled before the duration elapses.
func TestSleepCtx_Cancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	assert.False(t, sleepCtx(ctx, time.Minute))
}

// Ensures an already-attached counter is kept instead of replaced.
func TestRateLimitCounterContext_ExistingCounterWins(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	first := &atomic.Int64{}
	first.Add(1)

	ctx = withRateLimitCounter(ctx, first)

	second := &atomic.Int64{}
	second.Add(2)
	ctx = withRateLimitCounter(ctx, second)

	assert.Same(t, first, rateLimitCounterFromContext(ctx))
	assert.Equal(t, int64(1), rateLimitCounterFromContext(ctx).Load())
}
