package adapter

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

type SimpleLifecycle interface {
	Start() error
	Close() error
}

type StartStage uint8

const (
	StartStateInitialize StartStage = iota
	StartStateStart
	StartStatePostStart
	StartStateStarted
)

var ListStartStages = []StartStage{
	StartStateInitialize,
	StartStateStart,
	StartStatePostStart,
	StartStateStarted,
}

func (s StartStage) String() string {
	switch s {
	case StartStateInitialize:
		return "initialize"
	case StartStateStart:
		return "start"
	case StartStatePostStart:
		return "post-start"
	case StartStateStarted:
		return "finish-start"
	default:
		panic("unknown stage")
	}
}

type Lifecycle interface {
	Start(stage StartStage, scope *Scope) error
}

type LifecycleService interface {
	Name() string
	Lifecycle
}

type Scope struct {
	ctx      context.Context
	cancel   context.CancelFunc
	logger   log.ContextLogger
	access   sync.Mutex
	cleanups []func() error
	children map[Lifecycle]*Scope
}

func NewScope(ctx context.Context, logger log.ContextLogger) *Scope {
	ctx, cancel := context.WithCancel(ctx)
	return &Scope{
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger,
		children: make(map[Lifecycle]*Scope),
	}
}

func (s *Scope) Context() context.Context {
	return s.ctx
}

func (s *Scope) Add(cleanup func() error) {
	s.access.Lock()
	if s.ctx.Err() != nil {
		s.access.Unlock()
		// An in-flight startup can publish a resource after Close drained the
		// cleanup list. Close that resource immediately, without holding the
		// scope lock: cleanup itself can register or remove other resources.
		if err := cleanup(); err != nil && s.logger != nil {
			s.logger.Error("close late resource: ", err)
		}
		return
	}
	s.cleanups = append(s.cleanups, cleanup)
	s.access.Unlock()
}

func (s *Scope) Start(name string, component Lifecycle, stage StartStage) error {
	s.access.Lock()
	err := s.ctx.Err()
	if err != nil {
		s.access.Unlock()
		return err
	}
	child, loaded := s.children[component]
	if !loaded {
		child = NewScope(s.ctx, s.logger)
		s.children[component] = child
		s.cleanups = append(s.cleanups, func() error {
			done := LogElapsed(s.logger, "close ", name)
			monitor := taskmonitor.New(s.logger, C.StopTimeout)
			monitor.Start("close ", name)
			closeErr := child.Close()
			monitor.Finish()
			done()
			if closeErr != nil {
				return E.Cause(closeErr, "close ", name)
			}
			return nil
		})
	}
	s.access.Unlock()
	done := LogElapsed(s.logger, stage, " ", name)
	monitor := taskmonitor.New(s.logger, C.StartTimeout)
	monitor.Start(stage, " ", name)
	err = component.Start(stage, child)
	monitor.Finish()
	done()
	if err == nil {
		// Stop may have won while this startup stage was in flight.
		err = s.ctx.Err()
	}
	if err != nil {
		return E.Cause(err, stage, " ", name)
	}
	return nil
}

func (s *Scope) Close() error {
	s.access.Lock()
	s.cancel()
	cleanups := s.cleanups
	s.cleanups = nil
	s.children = nil
	s.access.Unlock()
	var cleanupErrors []error
	for _, cleanup := range slices.Backward(cleanups) {
		cleanupErrors = append(cleanupErrors, E.Expand(cleanup())...)
	}
	return E.Errors(common.Filter(cleanupErrors, func(it error) bool {
		return !expectedScopeCleanupError(it)
	})...)
}

// IsCanceled/IsClosed match any branch in an error tree. Only discard the
// whole error when every leaf is expected; a mixed wrapped failure must keep
// its original context and real causes rather than disappearing at shutdown.
func expectedScopeCleanupError(err error) bool {
	if multiple, ok := err.(interface{ Unwrap() []error }); ok {
		children := multiple.Unwrap()
		if len(children) == 0 {
			return E.IsClosed(err) || E.IsCanceled(err)
		}
		for _, child := range children {
			if child != nil && !expectedScopeCleanupError(child) {
				return false
			}
		}
		return true
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		if child := single.Unwrap(); child != nil {
			return expectedScopeCleanupError(child)
		}
	}
	return E.IsClosed(err) || E.IsCanceled(err)
}

func LogElapsed(logger log.ContextLogger, description ...any) func() {
	prefix := F.ToString(description...)
	startTime := time.Now()
	timer := time.AfterFunc(time.Second, func() {
		logger.Trace(prefix, "...")
	})
	return func() {
		if timer.Stop() {
			return
		}
		logger.Trace(prefix, " completed (", F.Seconds(time.Since(startTime).Seconds()), "s)")
	}
}
