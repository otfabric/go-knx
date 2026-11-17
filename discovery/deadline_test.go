// SPDX-License-Identifier: MIT

package discovery_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
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

// endingCalls are Search and Describe of the server at addr with a timeout
// (wait) that they do not reach: they end with their context.
var endingCalls = map[string]func(cx context.Context, addr string) error{
	"Search": func(cx context.Context, addr string) error {
		rs, err := discovery.Search(cx, discovery.WithUnicast(addr), discovery.WithTimeout(wait))
		if len(rs) != 0 {
			return errors.New("Search returned a result")
		}
		return err
	},
	"Describe": func(cx context.Context, addr string) error {
		dibs, err := discovery.Describe(cx, addr, discovery.WithTimeout(wait))
		if dibs != nil {
			return errors.New("Describe returned DIBs")
		}
		return err
	},
}

// ERR-R01: Search and Describe that end at their context's deadline return
// an error matching knx.ErrTimeout and context.DeadlineExceeded, whether
// the deadline had passed when they were called or passed while they
// waited for an answer. Cancelled, they match context.Canceled only.
func TestDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	for name, call := range endingCalls {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				err   func(t *testing.T, addr string, request <-chan struct{}) error
				check func(t *testing.T, err error, what string)
			}{
				{"the deadline had passed", func(t *testing.T, addr string, _ <-chan struct{}) error {
					cx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
					defer cancel()
					return call(cx, addr)
				}, isTimeout},
				{"the deadline passes while it waits", func(t *testing.T, addr string, request <-chan struct{}) error {
					dctx := newExpiringCtx()
					go func() {
						<-request
						dctx.expire()
					}()
					return call(dctx, addr)
				}, isTimeout},
				{"cancelled before", func(t *testing.T, addr string, _ <-chan struct{}) error {
					cx, cancel := context.WithCancel(context.Background())
					cancel()
					return call(cx, addr)
				}, isCanceled},
				{"cancelled while it waits", func(t *testing.T, addr string, request <-chan struct{}) error {
					cx, cancel := context.WithCancel(context.Background())
					defer cancel()
					go func() {
						<-request
						cancel()
					}()
					return call(cx, addr)
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

// prompt bounds how long Search and Describe take to return once their
// context has ended. Their own timeout (wait) is ten times as long: a read
// that ran to the deadline of a step would last a third of it (Describe)
// or all of it (Search).
const prompt = time.Second

// Search and Describe return as soon as their context ends, with the
// errors of TestDeadlineIsTimeout: when it had ended before the call, at
// once and without sending a request; when it ends while they wait for an
// answer, within prompt. Each row runs several times, as the order of the
// context's end and of the call's own read deadline is up to the
// scheduler. Real sockets: testing/synctest does not apply.
func TestEndedContextReturnsPromptly(t *testing.T) {
	leak.Check(t)
	const runs = 10
	for name, call := range endingCalls {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				// before is set when the context ends before the call.
				before bool
				// ctx returns the context of a call, which ends once
				// request receives (or at once), and the function that
				// ends it.
				ctx   func(request <-chan struct{}) (context.Context, func())
				check func(t *testing.T, err error, what string)
			}{
				{"the deadline had passed", true, func(<-chan struct{}) (context.Context, func()) {
					return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				}, isTimeout},
				{"cancelled before", true, func(<-chan struct{}) (context.Context, func()) {
					cx, cancel := context.WithCancel(context.Background())
					cancel()
					return cx, cancel
				}, isCanceled},
				{"the deadline passes while it waits", false, func(request <-chan struct{}) (context.Context, func()) {
					dctx := newExpiringCtx()
					go func() {
						select {
						case <-request:
						case <-dctx.Done():
						}
						dctx.expire()
					}()
					return dctx, dctx.expire
				}, isTimeout},
				{"cancelled while it waits", false, func(request <-chan struct{}) (context.Context, func()) {
					cx, cancel := context.WithCancel(context.Background())
					go func() {
						select {
						case <-request:
						case <-cx.Done():
						}
						cancel()
					}()
					return cx, cancel
				}, isCanceled},
			} {
				t.Run(tc.name, func(t *testing.T) {
					// The marker comes from a second socket after the call
					// returned: the server handles it after any request the
					// call sent, which is in its socket's queue before it.
					marker := fakeknx.Listen(t)
					for i := range runs {
						what := fmt.Sprintf("%s, %s (run %d)", name, tc.name, i+1)
						// A server that receives the requests and does not answer.
						p := fakeknx.Listen(t)
						request, marked := make(chan struct{}, 1), make(chan int, 1)
						requests := 0
						p.Handle(func(_ *fakeknx.Peer, d fakeknx.Datagram) bool {
							if d.From == marker.Addr() {
								marked <- requests
								return true
							}
							requests++
							select {
							case request <- struct{}{}:
							default:
							}
							return true
						})
						cx, end := tc.ctx(request)
						start := time.Now()
						err := call(cx, p.String())
						took := time.Since(start)
						end()
						tc.check(t, err, what)
						if took > prompt {
							t.Fatalf("%s: returned after %v, want within %v (its own timeout is %v)", what, took, prompt, wait)
						}
						if !tc.before {
							continue
						}
						marker.Send(p.Addr(), &knxnetip.SearchRequest{Discovery: marker.HPAI()})
						select {
						case n := <-marked:
							if n != 0 {
								t.Fatalf("%s: %d requests sent, want none", what, n)
							}
						case <-time.After(wait):
							t.Fatalf("%s: the server did not receive the marker", what)
						}
					}
				})
			}
		})
	}
}
