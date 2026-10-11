package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

func TestScopeCloseIgnoresExpectedCancellationAndClosedErrors(t *testing.T) {
	for _, cleanupError := range []error{context.Canceled, net.ErrClosed, fmt.Errorf("wrapped: %w", context.Canceled)} {
		scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
		scope.Add(func() error { return cleanupError })
		if err := scope.Close(); err != nil {
			t.Errorf("normal shutdown should not fail: %v", err)
		}
	}
}

func TestScopeClosePreservesRealFailureInMixedCleanupErrors(t *testing.T) {
	realFailure := errors.New("disk flush failed")
	scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
	var order []int
	scope.Add(func() error { order = append(order, 1); return context.Canceled })
	scope.Add(func() error { order = append(order, 2); return E.Errors(net.ErrClosed, realFailure) })
	err := scope.Close()
	if !errors.Is(err, realFailure) {
		t.Fatalf("lost actual failure: %v", err)
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		t.Errorf("expected shutdown errors leaked into result: %v", err)
	}
	if len(order) != 2 || order[0] != 2 || order[1] != 1 {
		t.Errorf("cleanup order changed: %v", order)
	}
}

func TestScopeClosePreservesRealFailureInWrappedJoinedErrors(t *testing.T) {
	realFailure := errors.New("disk flush failed")
	for _, join := range []func(...error) error{errors.Join, E.Errors} {
		scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
		scope.Add(func() error {
			return fmt.Errorf("flush: %w", join(context.Canceled, realFailure))
		})
		err := scope.Close()
		if !errors.Is(err, realFailure) {
			t.Errorf("lost real failure wrapped alongside cancellation: %v", err)
		}
		if err == nil || !strings.Contains(err.Error(), "flush:") {
			t.Errorf("lost wrapped cleanup context: %v", err)
		}
	}
}

func TestScopeCloseIgnoresNestedExpectedErrorTrees(t *testing.T) {
	scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
	scope.Add(func() error {
		return fmt.Errorf("outer: %w", errors.Join(
			fmt.Errorf("inner: %w", E.Errors(context.Canceled, net.ErrClosed)),
			context.Canceled,
		))
	})
	if err := scope.Close(); err != nil {
		t.Fatalf("expected nested shutdown errors leaked: %v", err)
	}
}

func TestScopeLateCleanupAfterCloseRunsOnce(t *testing.T) {
	scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	var cleaned atomic.Int32
	scope.Add(func() error {
		cleaned.Add(1)
		return nil
	})
	if got := cleaned.Load(); got != 1 {
		t.Fatalf("late resource was not closed: cleanups=%d", got)
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if got := cleaned.Load(); got != 1 {
		t.Fatalf("resource closed more than once: cleanups=%d", got)
	}
}

type lateCleanupLogger struct {
	log.ContextLogger
	errors atomic.Int32
}

func (l *lateCleanupLogger) Error(_ ...any) {
	l.errors.Add(1)
}

func TestScopeLateCleanupStillLogsRealFailure(t *testing.T) {
	logger := &lateCleanupLogger{}
	scope := NewScope(context.Background(), logger)
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	scope.Add(func() error { return errors.New("late resource cleanup failed") })
	if got := logger.errors.Load(); got != 1 {
		t.Fatalf("late cleanup failure was hidden: errors=%d", got)
	}
}

type blockedScopeStart struct {
	entered chan struct{}
	resume  chan struct{}
	cleaned atomic.Int32
}

func (c *blockedScopeStart) Start(_ StartStage, scope *Scope) error {
	close(c.entered)
	<-c.resume
	scope.Add(func() error {
		c.cleaned.Add(1)
		return nil
	})
	return nil
}

func TestScopeInFlightStartCleansAfterClose(t *testing.T) {
	scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
	component := &blockedScopeStart{entered: make(chan struct{}), resume: make(chan struct{})}
	result := make(chan error, 1)
	go func() { result <- scope.Start("blocked resource", component, StartStateStart) }()
	select {
	case <-component.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("resource startup did not enter")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	close(component.resume)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("closed scope reported successful startup: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup remained blocked after close")
	}
	if got := component.cleaned.Load(); got != 1 {
		t.Fatalf("resource registered during close leaked: cleanups=%d", got)
	}
}

func TestScopeLateCleanupCanRegisterAnotherCleanup(t *testing.T) {
	scope := NewScope(context.Background(), log.NewNOPFactory().Logger())
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	var cleaned atomic.Int32
	done := make(chan struct{})
	go func() {
		scope.Add(func() error {
			scope.Add(func() error { cleaned.Add(1); return nil })
			cleaned.Add(1)
			return nil
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup deadlocked on scope lock")
	}
	if got := cleaned.Load(); got != 2 {
		t.Fatalf("nested late cleanup leaked: cleanups=%d", got)
	}
}
