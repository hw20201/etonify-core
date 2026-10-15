package etonifydesktop

import (
	"context"
	"sync"
)

type responseFenceKey struct{}
type responseFence struct {
	mu                 sync.Mutex
	done               chan struct{}
	closed             bool
	releases           []func()
	published, written int
	sealed, responded  bool
}

func newResponseFence() *responseFence   { return &responseFence{done: make(chan struct{})} }
func (f *responseFence) publishedChunk() { f.mu.Lock(); f.published++; f.mu.Unlock() }
func (f *responseFence) chunkWritten()   { f.mu.Lock(); f.written++; f.completeLocked(); f.mu.Unlock() }
func (f *responseFence) seal()           { f.mu.Lock(); f.sealed = true; f.completeLocked(); f.mu.Unlock() }
func (f *responseFence) responseWritten() {
	f.mu.Lock()
	f.responded = true
	f.completeLocked()
	f.mu.Unlock()
}
func (f *responseFence) completeLocked() {
	if f.sealed && f.responded && f.written == f.published {
		f.finishLocked()
	}
}
func (f *responseFence) own(release func()) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		release()
		return
	}
	f.releases = append(f.releases, release)
	f.mu.Unlock()
}
func (f *responseFence) finish() {
	f.mu.Lock()
	f.finishLocked()
	f.mu.Unlock()
}
func (f *responseFence) finishLocked() {
	if f.closed {
		return
	}
	f.closed = true
	for _, release := range f.releases {
		release()
	}
	f.releases = nil
	close(f.done)
}
func (h *Host) initChunkFlow() {
	h.chunkInit.Do(func() {
		h.rpcChunkSlots = make(chan struct{}, 3)
		h.subscriptionChunkSlot = make(chan struct{}, 1)
	})
}
func (h *Host) leaseChunkReply(ctx context.Context) (func(), error) {
	h.initChunkFlow()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case h.rpcChunkSlots <- struct{}{}:
	default:
		return nil, runtimeFailure("busy", "Large desktop reply capacity is busy; retry the request")
	}
	var once sync.Once
	release := func() { once.Do(func() { <-h.rpcChunkSlots }) }
	if fence, ok := ctx.Value(responseFenceKey{}).(*responseFence); ok {
		fence.own(release)
		return func() {}, nil // Wire owns the slot until the descriptor/error is written.
	}
	return release, nil // Direct in-process use has no pending wire response.
}
