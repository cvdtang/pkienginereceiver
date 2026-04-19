package pkienginereceiver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestScrapeTaskPoolDrainsDynamicallySubmittedTasks(t *testing.T) {
	t.Parallel()

	pool := newScrapeTaskPool(context.Background(), 2)

	var executed atomic.Int64
	pool.submit(func() {
		executed.Add(1)
		for range 5 {
			pool.submit(func() {
				executed.Add(1)
			})
		}
	})

	pool.wait()

	assert.Equal(t, int64(6), executed.Load())
}

func TestScrapeTaskPoolRecursiveEnqueueNoDeadlock(t *testing.T) {
	t.Parallel()

	const depth = 5000
	pool := newScrapeTaskPool(context.Background(), 1)

	var executed atomic.Int64
	var enqueue func(level int)
	enqueue = func(level int) {
		executed.Add(1)
		if level == 0 {
			return
		}

		pool.submit(func() {
			enqueue(level - 1)
		})
	}

	pool.submit(func() {
		enqueue(depth)
	})

	pool.wait()

	assert.Equal(t, int64(depth+1), executed.Load())
}

func TestScrapeTaskPoolBoundedSchedulerGoroutines(t *testing.T) {
	t.Parallel()

	pool := newScrapeTaskPool(context.Background(), 1)

	var inFlight atomic.Int64
	var maxInFlight atomic.Int64
	withInFlightAccounting := func(taskFn func()) func() {
		return func() {
			current := inFlight.Add(1)
			for {
				prev := maxInFlight.Load()
				if current <= prev {
					break
				}
				if maxInFlight.CompareAndSwap(prev, current) {
					break
				}
			}
			defer inFlight.Add(-1)

			taskFn()
		}
	}

	started := make(chan struct{})
	submittedFanout := make(chan struct{})
	releaseFirst := make(chan struct{})
	const fanout = 30000
	pool.submit(withInFlightAccounting(func() {
		close(started)
		for range fanout {
			pool.submit(withInFlightAccounting(func() {}))
		}
		close(submittedFanout)
		<-releaseFirst
	}))

	<-started
	<-submittedFanout
	close(releaseFirst)
	pool.wait()

	assert.Equal(t, int64(1), maxInFlight.Load())
}

func TestScrapeTaskPoolWaitReturnsAfterContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	pool := newScrapeTaskPool(ctx, 1)

	started := make(chan struct{})
	release := make(chan struct{})
	var executed atomic.Int64

	pool.submit(func() {
		executed.Add(1)
		close(started)
		<-release
		pool.submit(func() {
			executed.Add(1)
		})
	})

	<-started
	cancel()
	close(release)

	done := make(chan struct{})
	go func() {
		pool.wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pool wait did not return after context cancellation")
	}

	assert.Equal(t, int64(1), executed.Load())
}
