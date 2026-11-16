// SPDX-License-Identifier: MIT

package discovery_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
)

// wait bounds a wait that would otherwise hang.
const wait = 10 * time.Second

// isTimeout fails the test unless err matches knx.ErrTimeout and
// context.DeadlineExceeded, and its message names the package once.
func isTimeout(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%s = %v, want an error matching knx.ErrTimeout and context.DeadlineExceeded", what, err)
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "knx: timeout: discovery: ") || strings.Contains(msg, "discovery: discovery: ") {
		t.Fatalf("%s: message %q, want it to start with \"knx: timeout: discovery: \" and name the package once", what, msg)
	}
}

// isCanceled fails the test unless err matches context.Canceled and
// nothing else of a deadline.
func isCanceled(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%s = %v, want an error matching context.Canceled only", what, err)
	}
}

// expiringCtx is a context whose deadline the test ends: expire ends it
// with context.DeadlineExceeded.
type expiringCtx struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newExpiringCtx() *expiringCtx {
	return &expiringCtx{Context: context.Background(), done: make(chan struct{})}
}

func (e *expiringCtx) Done() <-chan struct{} { return e.done }

func (e *expiringCtx) Err() error {
	select {
	case <-e.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (e *expiringCtx) Deadline() (time.Time, bool) { return time.Now().Add(time.Hour), true }

func (e *expiringCtx) expire() { e.once.Do(func() { close(e.done) }) }

// ERR-R01: Search and Describe that end at their context's deadline return
// an error matching knx.ErrTimeout and context.DeadlineExceeded, whether
// the deadline had passed when they were called or passed while they
// waited for an answer. Cancelled, they match context.Canceled only.
func TestDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	// A call whose context has already ended may read until its timeout
	// before it reports the context; a short one keeps those rows short.
	// The rows that end the context while the call waits give it a timeout
	// it does not reach.
	const short = 300 * time.Millisecond
	calls := map[string]func(cx context.Context, addr string, timeout time.Duration) error{
		"Search": func(cx context.Context, addr string, timeout time.Duration) error {
			rs, err := discovery.Search(cx, discovery.WithUnicast(addr), discovery.WithTimeout(timeout))
			if len(rs) != 0 {
				return errors.New("Search returned a result")
			}
			return err
		},
		"Describe": func(cx context.Context, addr string, timeout time.Duration) error {
			dibs, err := discovery.Describe(cx, addr, discovery.WithTimeout(timeout))
			if dibs != nil {
				return errors.New("Describe returned DIBs")
			}
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				err   func(t *testing.T, addr string, request <-chan struct{}) error
				check func(t *testing.T, err error, what string)
			}{
				{"the deadline had passed", func(t *testing.T, addr string, _ <-chan struct{}) error {
					cx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
					defer cancel()
					return call(cx, addr, short)
				}, isTimeout},
				{"the deadline passes while it waits", func(t *testing.T, addr string, request <-chan struct{}) error {
					dctx := newExpiringCtx()
					go func() {
						<-request
						dctx.expire()
					}()
					return call(dctx, addr, wait)
				}, isTimeout},
				{"cancelled before", func(t *testing.T, addr string, _ <-chan struct{}) error {
					cx, cancel := context.WithCancel(context.Background())
					cancel()
					return call(cx, addr, short)
				}, isCanceled},
				{"cancelled while it waits", func(t *testing.T, addr string, request <-chan struct{}) error {
					cx, cancel := context.WithCancel(context.Background())
					defer cancel()
					go func() {
						<-request
						cancel()
					}()
					return call(cx, addr, wait)
				}, isCanceled},
			} {
				t.Run(tc.name, func(t *testing.T) {
					// A server that receives the requests and does not answer.
					p := fakeknx.Listen(t)
					request := make(chan struct{}, 3)
					p.Handle(func(*fakeknx.Peer, fakeknx.Datagram) bool {
						select {
						case request <- struct{}{}:
						default:
						}
						return true
					})
					tc.check(t, tc.err(t, p.String(), request), name+", "+tc.name)
				})
			}
		})
	}
}
