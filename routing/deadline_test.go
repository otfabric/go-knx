// SPDX-License-Identifier: MIT

package routing_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/routing"
)

// isTimeout fails the test unless err matches knx.ErrTimeout and
// context.DeadlineExceeded, and its message names the package once.
func isTimeout(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%s = %v, want an error matching knx.ErrTimeout and context.DeadlineExceeded", what, err)
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "knx: timeout: routing: ") || strings.Contains(msg, "routing: routing: ") {
		t.Fatalf("%s: message %q, want it to start with \"knx: timeout: routing: \" and name the package once", what, msg)
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

// ERR-R01: a Send whose context deadline passes returns an error matching
// knx.ErrTimeout and context.DeadlineExceeded, whether it waited for the
// pause after a ROUTING_BUSY, for its turn behind a Send in that pause, or
// reached the write with the deadline already passed (nothing is sent). A
// cancelled Send matches context.Canceled only.
func TestSendDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)

	t.Run("the write", func(t *testing.T) {
		c, m, _, _ := listen(t, routing.WithRate(0))
		past, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		isTimeout(t, c.Send(past, frame(1)), "Send whose deadline had passed")
		if n := m.get(func(m *metrics) int { return m.sent }); n != 0 {
			t.Fatalf("%d frames sent after the deadline, want 0", n)
		}
	})

	t.Run("the pause and the turn", func(t *testing.T) {
		c, _, _, local := listen(t, routing.WithRate(0))
		p := fakeknx.Listen(t)
		p.Send(local, &knxnetip.RoutingBusy{WaitTime: 60000})
		recv(t, c.Events(), "the ROUTING_BUSY event")

		// A deadline in the pause.
		short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		isTimeout(t, c.Send(short, frame(1)), "Send whose deadline passed in the pause after a ROUTING_BUSY")

		// A deadline while another Send waits in the pause.
		holder := newWaitCtx(context.Background())
		held := make(chan error, 1)
		go func() { held <- c.Send(holder, frame(2)) }()
		recv(t, holder.waiting, "the first Send to wait in the pause")
		turn, cancelTurn := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancelTurn()
		isTimeout(t, c.Send(turn, frame(3)), "Send whose deadline passed while it waited for its turn")

		// Cancellation is not a deadline.
		cctx, cancelSend := context.WithCancel(context.Background())
		waiting := newWaitCtx(cctx)
		errc := make(chan error, 1)
		go func() { errc <- c.Send(waiting, frame(4)) }()
		recv(t, waiting.waiting, "the cancelled Send to wait for its turn")
		cancelSend()
		if err := recv(t, errc, "the cancelled Send to return"); !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) {
			t.Fatalf("cancelled Send = %v, want an error matching context.Canceled only", err)
		}
		c.Close()
		if err := recv(t, held, "the paused Send to return after Close"); !errors.Is(err, knx.ErrClosed) {
			t.Fatalf("Send in the pause at Close = %v, want knx.ErrClosed", err)
		}
	})
}

// ERR-R01: Listen with WithSecure whose context deadline passes inside the
// timer synchronisation window returns an error matching knx.ErrTimeout
// and context.DeadlineExceeded, and no Conn; a cancelled one matches
// context.Canceled only.
func TestListenDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	_, _, g, _ := listen(t) // skips where the group cannot be joined
	opts := []routing.Option{routing.WithGroup(g.String()), routing.WithSecure(backbone, 100*time.Millisecond)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		opts = append(opts, routing.WithInterface(lo))
	}
	// The window is 420 ms at this latency.
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	c, err := routing.Listen(short, opts...)
	if c != nil {
		c.Close()
		t.Fatal("Listen returned a Conn although its deadline passed inside the synchronisation window")
	}
	isTimeout(t, err, "Listen whose deadline passed inside the synchronisation window")

	cctx, cancelListen := context.WithCancel(context.Background())
	cancelListen()
	c, err = routing.Listen(cctx, opts...)
	if c != nil {
		c.Close()
		t.Fatal("Listen returned a Conn although its context was cancelled")
	}
	if !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("cancelled Listen = %v, want an error matching context.Canceled only", err)
	}
}

// ERR-R01: a Receive that ends at its context's deadline returns an error
// matching knx.ErrTimeout and context.DeadlineExceeded, whether the
// deadline had passed when it was called or passed while it waited for a
// frame. A cancelled Receive matches context.Canceled only.
func TestReceiveDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	receiveErr := func(c *routing.Conn, cx context.Context) <-chan error {
		ch := make(chan error, 1)
		go func() {
			f, err := c.Receive(cx)
			if f != nil {
				err = errors.New("Receive returned a frame")
			}
			ch <- err
		}()
		return ch
	}
	for _, tc := range []struct {
		name  string
		err   func(t *testing.T, c *routing.Conn) error
		check func(t *testing.T, err error, what string)
	}{
		{"the deadline had passed", func(t *testing.T, c *routing.Conn) error {
			cx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer cancel()
			return recv(t, receiveErr(c, cx), "Receive to return")
		}, isTimeout},
		{"the deadline passes while it waits", func(t *testing.T, c *routing.Conn) error {
			dctx := newExpiringCtx()
			waiting := newWaitCtx(dctx)
			res := receiveErr(c, waiting)
			recv(t, waiting.waiting, "Receive to wait for a frame")
			dctx.expire()
			return recv(t, res, "Receive to return")
		}, isTimeout},
		{"cancelled before", func(t *testing.T, c *routing.Conn) error {
			cx, cancel := context.WithCancel(context.Background())
			cancel()
			return recv(t, receiveErr(c, cx), "Receive to return")
		}, isCanceled},
		{"cancelled while it waits", func(t *testing.T, c *routing.Conn) error {
			cx, cancel := context.WithCancel(context.Background())
			defer cancel()
			waiting := newWaitCtx(cx)
			res := receiveErr(c, waiting)
			recv(t, waiting.waiting, "Receive to wait for a frame")
			cancel()
			return recv(t, res, "Receive to return")
		}, isCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _, _ := listen(t)
			tc.check(t, tc.err(t, c), "Receive, "+tc.name)
		})
	}
}
