package pkienginereceiver

// Small worker-pool + task queue that supports dynamically enqueued tasks and
// waits for all submitted work to finish before shutting down the workers.
// A plain channel+WaitGroup isn't enough here because tasks can enqueue more
// tasks; safely closing a channel would require extra coordination.

import (
	"context"
	"sync"
)

type taskFunc func(context.Context)

type taskRunner struct {
	ctx     context.Context
	queue   *taskQueue
	counter *taskCounter
	workers sync.WaitGroup
}

// Creates a task runner with a worker pool and shared queue.
func newTaskRunner(ctx context.Context, workerCount int) *taskRunner {
	// Always keep at least one worker available.
	if workerCount < 1 {
		workerCount = 1
	}

	runner := &taskRunner{
		ctx:     ctx,
		queue:   newTaskQueue(),
		counter: newTaskCounter(),
	}

	runner.workers.Add(workerCount)
	for range workerCount {
		go runner.worker()
	}

	return runner
}

// Submits a task if the runner is active and the queue accepts it.
func (r *taskRunner) enqueue(task taskFunc) {
	if task == nil {
		return
	}
	if r.ctx.Err() != nil {
		return
	}

	r.counter.Add(1)
	if !r.queue.push(task) {
		// Queue closed while enqueueing; undo the task count.
		r.counter.Done()
	}
}

// Blocks until all queued work is completed and workers exit.
func (r *taskRunner) wait() {
	// Stop accepting work only after all pending tasks are done.
	r.counter.Wait()
	r.queue.close()
	r.workers.Wait()
}

// Processes tasks from the queue until it is closed.
func (r *taskRunner) worker() {
	defer r.workers.Done()

	for {
		task, ok := r.queue.pop()
		if !ok {
			return
		}

		if r.ctx.Err() == nil {
			task(r.ctx)
		}

		r.counter.Done()
	}
}

type taskQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	tasks  []taskFunc
	closed bool
}

// Creates a synchronized in-memory task queue.
func newTaskQueue() *taskQueue {
	q := &taskQueue{}
	q.cond = sync.NewCond(&q.mu)

	return q
}

// Appends a task to the queue unless the queue is closed.
func (q *taskQueue) push(task taskFunc) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return false
	}

	q.tasks = append(q.tasks, task)
	q.cond.Signal()

	return true
}

// Blocks until a task is available or the queue is closed.
func (q *taskQueue) pop() (taskFunc, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Sleep until work arrives or the queue is closed.
	for len(q.tasks) == 0 && !q.closed {
		q.cond.Wait()
	}

	if len(q.tasks) == 0 {
		return nil, false
	}

	task := q.tasks[0]
	// Clear the slot to release references promptly.
	q.tasks[0] = nil
	q.tasks = q.tasks[1:]

	return task, true
}

// Marks the queue as closed and wakes blocked workers.
func (q *taskQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

type taskCounter struct {
	mu    sync.Mutex
	cond  *sync.Cond
	count int
}

// Creates a synchronized counter for queued work.
func newTaskCounter() *taskCounter {
	c := &taskCounter{}
	c.cond = sync.NewCond(&c.mu)

	return c
}

// Adjust the task counter and unblocks waiters once all tasks are done.
func (c *taskCounter) Add(delta int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count += delta

	if c.count < 0 {
		c.count = 0
	}

	if c.count == 0 {
		c.cond.Broadcast()
	}
}

// Mark a single task as completed.
func (c *taskCounter) Done() {
	c.Add(-1)
}

// Block until the outstanding task count drops to zero.
func (c *taskCounter) Wait() {
	c.mu.Lock()
	for c.count > 0 {
		c.cond.Wait()
	}
	c.mu.Unlock()
}
