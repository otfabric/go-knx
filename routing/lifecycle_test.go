// SPDX-License-Identifier: MIT

package routing_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/routing"
)

// Lifecycle contract tests (TESTING.md, "Lifecycle contract matrix"). Every
// wait is on an event: a frame, a value on a channel, a context that
// reports when a call starts to wait on it. The constant wait only bounds a
// wait that would otherwise hang.

// waitCtx is a context that reports when a call starts to wait on it: Send
// asks for Done when it begins a wait that the context can end.
type waitCtx struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func newWaitCtx(parent context.Context) *waitCtx {
	return &waitCtx{Context: parent, waiting: make(chan struct{})}
}

func (w *waitCtx) Done() <-chan struct{} {
	w.once.Do(func() { close(w.waiting) })
	return w.Context.Done()
}

// recv returns the next value of ch, or fails the test naming what did not
// arrive.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	var v T
	select {
	case v = <-ch:
	case <-time.After(wait):
		t.Fatalf("timed out waiting for %s", what)
	}
	return v
}

// openFDs returns the number of open file descriptors of the process, or
// -1 where /dev/fd is not available.
func openFDs() int {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// L4 for Send: a Send waits for its turn behind one that waits out a flow
// control pause, and that wait ends with the caller's context or with
// Close, like the pause itself.
func TestSendTurnEndsWithContextAndClose(t *testing.T) {
	leak.Check(t)
	c, _, _, local := listen(t, routing.WithRate(0))
	p := fakeknx.Listen(t)
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 60000})
	if ev := recv(t, c.Events(), "the ROUTING_BUSY event"); ev.Busy == nil {
		t.Fatalf("event %+v", ev)
	}

	// The holder: it has the turn and waits for the pause to end.
	holder := newWaitCtx(context.Background())
	held := make(chan error, 1)
	go func() { held <- c.Send(holder, frame(1)) }()
	recv(t, holder.waiting, "the first Send to wait in the pause")

	// A deadline ends the wait for the turn.
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- c.Send(short, frame(2)) }()
	if err := recv(t, errc, "the Send with a deadline to return"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send with a deadline behind a paused Send = %v, want context.DeadlineExceeded", err)
	}

	// So does cancellation, once the Send waits.
	cctx, cancelSend := context.WithCancel(context.Background())
	second := newWaitCtx(cctx)
	go func() { errc <- c.Send(second, frame(3)) }()
	recv(t, second.waiting, "the second Send to wait for its turn")
	cancelSend()
	if err := recv(t, errc, "the cancelled Send to return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Send behind a paused Send = %v, want context.Canceled", err)
	}

	// Close ends both: the Send that waits for its turn and the holder.
	third := newWaitCtx(context.Background())
	go func() { errc <- c.Send(third, frame(4)) }()
	recv(t, third.waiting, "the third Send to wait for its turn")
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recv(t, errc, "the waiting Send to return after Close"); !errors.Is(err, knx.ErrClosed) {
		t.Errorf("Send waiting for its turn at Close = %v, want knx.ErrClosed", err)
	}
	if err := recv(t, held, "the paused Send to return after Close"); !errors.Is(err, knx.ErrClosed) {
		t.Errorf("Send in the pause at Close = %v, want knx.ErrClosed", err)
	}
}

// The turn is passed on: after a Send left the queue, the others still send
// in order of arrival once the pause ends.
func TestSendTurnPassedOn(t *testing.T) {
	leak.Check(t)
	c, m, _, local := listen(t, routing.WithRate(0))
	p := fakeknx.Listen(t)
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 150})
	recv(t, c.Events(), "the ROUTING_BUSY event")
	holder := newWaitCtx(context.Background())
	errc := make(chan error, 3)
	go func() { errc <- c.Send(holder, frame(1)) }()
	recv(t, holder.waiting, "the first Send to wait in the pause")
	gone, cancel := context.WithCancel(context.Background())
	leaving := newWaitCtx(gone)
	left := make(chan error, 1)
	go func() { left <- c.Send(leaving, frame(2)) }()
	recv(t, leaving.waiting, "the second Send to wait for its turn")
	cancel()
	if err := recv(t, left, "the cancelled Send"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Send = %v", err)
	}
	go func() { errc <- c.Send(context.Background(), frame(3)) }()
	for i := range 2 {
		if err := recv(t, errc, "a Send after the pause"); err != nil {
			t.Fatalf("Send %d after the pause: %v", i, err)
		}
	}
	if n := m.get(func(m *metrics) int { return m.sent }); n != 2 {
		t.Errorf("%d indications sent, want 2 (the cancelled one is not sent)", n)
	}
}

// L2: Close from several goroutines; every call returns, the reader has
// ended and the descriptors are released once.
func TestCloseConcurrently(t *testing.T) {
	leak.Check(t)
	listen(t) // the first socket of the process initialises the poller
	before := openFDs()
	c, _, _, _ := listen(t)
	blocked := make(chan error, 1)
	rctx := newWaitCtx(context.Background())
	go func() { _, err := c.Receive(rctx); blocked <- err }()
	recv(t, rctx.waiting, "Receive to block")
	const closers = 8
	start := make(chan struct{})
	errs := make(chan error, closers)
	for range closers {
		go func() {
			<-start
			errs <- c.Close()
		}()
	}
	close(start)
	for range closers {
		if err := recv(t, errs, "a Close to return"); err != nil {
			t.Errorf("Close = %v", err)
		}
	}
	if err := recv(t, blocked, "the blocked Receive"); !errors.Is(err, knx.ErrClosed) {
		t.Errorf("Receive at Close = %v, want knx.ErrClosed", err)
	}
	if after := openFDs(); before >= 0 && after != before {
		t.Errorf("%d descriptors open after Close, %d before Listen", after, before)
	}
}
