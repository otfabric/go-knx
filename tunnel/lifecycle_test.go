// SPDX-License-Identifier: MIT

package tunnel_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/tunnel"
)

// Lifecycle contract tests (TESTING.md, "Lifecycle contract matrix"). Every
// wait is on an event: a frame the fake server received, a value on a
// channel, a context that reports when a call starts to wait on it. The
// constant wait only bounds a wait that would otherwise hang.

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

// stepCtx is a context that reports every wait a call starts on it: a
// Send of an L_Data.req waits once for the acknowledgement and once for
// the confirmation.
type stepCtx struct {
	context.Context
	steps chan struct{}
}

func newStepCtx(parent context.Context) *stepCtx {
	return &stepCtx{Context: parent, steps: make(chan struct{}, 16)}
}

func (s *stepCtx) Done() <-chan struct{} {
	select {
	case s.steps <- struct{}{}:
	default:
	}
	return s.Context.Done()
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

func value(t *testing.T, req *knxnetip.TunnellingRequest) byte {
	t.Helper()
	f, err := cemi.Parse(req.CEMI)
	if err != nil {
		t.Fatal(err)
	}
	tpdu := f.(*cemi.LData).TPDU
	return tpdu[len(tpdu)-1]
}

// watch counts the tunnelling requests the fake server receives and
// reports the client's DISCONNECT_REQUEST; it consumes neither.
type watch struct {
	requests     atomic.Int32
	disconnected chan struct{}
	once         sync.Once
}

func newWatch(p *fakeknx.Peer) *watch {
	w := &watch{disconnected: make(chan struct{})}
	p.Handle(func(_ *fakeknx.Peer, d fakeknx.Datagram) bool {
		switch d.Msg.(type) {
		case *knxnetip.TunnellingRequest:
			w.requests.Add(1)
		case *knxnetip.DisconnectRequest:
			w.once.Do(func() { close(w.disconnected) })
		}
		return false
	})
	return w
}

// L6: a Send whose context ends between its request and the
// TUNNELLING_ACK leaves the request outstanding. Its sequence number
// carries no other frame: the next Send waits for that acknowledgement
// and then uses the next number, or loses the connection when the
// acknowledgement does not come.
func TestSendContextEndsBeforeAck(t *testing.T) {
	leak.Check(t)

	// cancelled sends the frame 0xA1 and leaves when the fake server has
	// the request.
	cancelled := func(t *testing.T, f *fixture) *knxnetip.TunnellingRequest {
		t.Helper()
		cx, cancel := context.WithCancel(context.Background())
		defer cancel()
		res := f.sendCtx(cx, groupWrite(0xA1))
		req := f.expectRequest()
		cancel()
		if err := result(t, res); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled Send = %v, want context.Canceled", err)
		}
		return req
	}

	t.Run("acknowledged while the next Send waits", func(t *testing.T) {
		f := dial(t, tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(time.Minute))
		first := cancelled(t, f)
		next := newWaitCtx(context.Background())
		res := f.sendCtx(next, groupWrite(0xC3))
		recv(t, next.waiting, "the next Send to wait")
		f.ack(first.Seq, knxnetip.StatusNoError)
		second := f.expectRequest()
		if second.Seq != first.Seq+1 || value(t, second) != 0xC3 {
			t.Fatalf("after a request with sequence %d whose caller left: request with sequence %d and value %#x, want sequence %d and value 0xc3",
				first.Seq, second.Seq, value(t, second), first.Seq+1)
		}
		f.ack(second.Seq, knxnetip.StatusNoError)
		if err := result(t, res); err != nil {
			t.Fatal(err)
		}
		if n := f.m.get(func(m *metrics) int { return m.retransmits }); n != 0 {
			t.Errorf("%d repetitions, want none", n)
		}
	})

	t.Run("acknowledged before the next Send", func(t *testing.T) {
		f := dial(t, tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(time.Minute))
		first := cancelled(t, f)
		f.ack(first.Seq, knxnetip.StatusNoError)
		// A marker after the acknowledgement: once it is delivered, the
		// reader has taken the acknowledgement.
		f.inbound(0, indication(9))
		receive(t, f.c)
		res := f.send(groupWrite(0xC3))
		second := f.expectRequest()
		if second.Seq != first.Seq+1 || value(t, second) != 0xC3 {
			t.Fatalf("request with sequence %d and value %#x, want sequence %d and value 0xc3", second.Seq, value(t, second), first.Seq+1)
		}
		f.ack(second.Seq, knxnetip.StatusNoError)
		if err := result(t, res); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("refused", func(t *testing.T) {
		f := dial(t, tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(time.Minute))
		first := cancelled(t, f)
		f.ack(first.Seq, knxnetip.StatusSequenceNumber)
		// A refused request does not consume its sequence number.
		res := f.send(groupWrite(0xC3))
		second := f.expectRequest()
		if second.Seq != first.Seq || value(t, second) != 0xC3 {
			t.Fatalf("request with sequence %d and value %#x, want sequence %d and value 0xc3", second.Seq, value(t, second), first.Seq)
		}
		f.ack(second.Seq, knxnetip.StatusNoError)
		if err := result(t, res); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("never acknowledged", func(t *testing.T) {
		p := fakeknx.Listen(t)
		w := newWatch(p)
		p.Handle(fakeknx.AnswerDisconnect)
		f := dialPeer(t, p, tunnel.WithConfirm(false, 0))
		cancelled(t, f)
		if err := f.c.Send(ctx(t), groupWrite(0xC3)); !errors.Is(err, knx.ErrConnectionLost) {
			t.Fatalf("Send after a request that was never acknowledged = %v, want knx.ErrConnectionLost", err)
		}
		// Every later call reports the same until the Conn has closed.
		if err := f.c.Send(ctx(t), groupWrite(0xD4)); !errors.Is(err, knx.ErrConnectionLost) && !errors.Is(err, knx.ErrClosed) {
			t.Fatalf("second Send = %v", err)
		}
		recv(t, f.c.Done(), "the Conn to close")
		if err := f.c.Err(); !errors.Is(err, knx.ErrConnectionLost) {
			t.Errorf("Err() = %v, want knx.ErrConnectionLost", err)
		}
		// The client's DISCONNECT_REQUEST is the last frame it wrote.
		recv(t, w.disconnected, "the DISCONNECT_REQUEST")
		if n := w.requests.Load(); n != 1 {
			t.Errorf("%d tunnelling requests written, want 1: the request is not repeated and its sequence number carries no other frame", n)
		}
	})

	t.Run("the wait ends with the caller's context and with Close", func(t *testing.T) {
		f := dial(t, tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(time.Minute))
		first := cancelled(t, f)
		cx, cancel := context.WithCancel(context.Background())
		next := newWaitCtx(cx)
		res := f.sendCtx(next, groupWrite(0xC3))
		recv(t, next.waiting, "the next Send to wait")
		cancel()
		if err := result(t, res); !errors.Is(err, context.Canceled) {
			t.Fatalf("Send = %v, want context.Canceled", err)
		}
		// The first request is still outstanding.
		third := newWaitCtx(context.Background())
		res = f.sendCtx(third, groupWrite(0xD4))
		recv(t, third.waiting, "the third Send to wait")
		f.ack(first.Seq, knxnetip.StatusNoError)
		req := f.expectRequest()
		if req.Seq != first.Seq+1 || value(t, req) != 0xD4 {
			t.Fatalf("request with sequence %d and value %#x, want sequence %d and value 0xd4", req.Seq, value(t, req), first.Seq+1)
		}
		f.c.Close()
		if err := result(t, res); !errors.Is(err, knx.ErrClosed) {
			t.Fatalf("Send at Close = %v, want knx.ErrClosed", err)
		}
	})

	t.Run("Close while the next Send waits", func(t *testing.T) {
		f := dial(t, tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(time.Minute))
		cancelled(t, f)
		next := newWaitCtx(context.Background())
		res := f.sendCtx(next, groupWrite(0xC3))
		recv(t, next.waiting, "the next Send to wait")
		f.c.Close()
		if err := result(t, res); !errors.Is(err, knx.ErrClosed) {
			t.Fatalf("Send at Close = %v, want knx.ErrClosed", err)
		}
	})
}

// Sends take turns, and the wait for the turn ends with the caller's
// context or with Close while another Send waits for its acknowledgement.
func TestSendTurnEndsWithContextAndClose(t *testing.T) {
	leak.Check(t)
	f := dial(t, tunnel.WithRequestTimeout(time.Minute))
	held := f.send(groupWrite(1))
	first := f.expectRequest() // the holder of the turn waits for its ACK

	short, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	if err := result(t, f.sendCtx(short, groupWrite(2))); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send with a deadline behind a Send that waits for its ACK = %v, want context.DeadlineExceeded", err)
	}

	cx, cancel := context.WithCancel(context.Background())
	second := newWaitCtx(cx)
	res := f.sendCtx(second, groupWrite(3))
	recv(t, second.waiting, "the second Send to wait for its turn")
	cancel()
	if err := result(t, res); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Send behind a Send that waits for its ACK = %v, want context.Canceled", err)
	}

	// A feature call takes the same turn.
	fcx, cancelFeature := context.WithCancel(context.Background())
	feature := newWaitCtx(fcx)
	ferr := make(chan error, 1)
	go func() { _, err := f.c.FeatureGet(feature, knxnetip.FeatureIndividualAddress); ferr <- err }()
	recv(t, feature.waiting, "the feature call to wait for its turn")
	cancelFeature()
	if err := result(t, ferr); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled FeatureGet behind a Send = %v, want context.Canceled", err)
	}

	// The turn is passed on when the holder is done.
	third := newWaitCtx(context.Background())
	res = f.sendCtx(third, groupWrite(4))
	recv(t, third.waiting, "the third Send to wait for its turn")
	f.ack(first.Seq, knxnetip.StatusNoError)
	f.confirm(first, 0, false)
	if err := result(t, held); err != nil {
		t.Fatal(err)
	}
	next := f.expectRequest()
	if next.Seq != first.Seq+1 || value(t, next) != 4 {
		t.Fatalf("request with sequence %d and value %d, want sequence %d and value 4", next.Seq, value(t, next), first.Seq+1)
	}

	// Close ends the wait for the turn and the wait for the ACK.
	fourth := newWaitCtx(context.Background())
	waiting := f.sendCtx(fourth, groupWrite(5))
	recv(t, fourth.waiting, "the fourth Send to wait for its turn")
	f.c.Close()
	for name, ch := range map[string]<-chan error{"the Send that waits for its turn": waiting, "the Send that waits for its ACK": res} {
		if err := result(t, ch); !errors.Is(err, knx.ErrClosed) {
			t.Errorf("%s at Close = %v, want knx.ErrClosed", name, err)
		}
	}
}

type featureResult struct {
	value []byte
	err   error
}

func (f *fixture) featureGet(id knxnetip.FeatureID) <-chan featureResult {
	ch := make(chan featureResult, 1)
	go func() {
		v, err := f.c.FeatureGet(context.Background(), id)
		ch <- featureResult{v, err}
	}()
	return ch
}

func (f *fixture) expectFeature() *knxnetip.TunnellingFeature {
	f.t.Helper()
	m, _ := fakeknx.Expect[*knxnetip.TunnellingFeature](f.p, wait)
	return m
}

// A feature request over UDP is acknowledged and repeated like a
// tunnelling request, and consumes its sequence number when acknowledged.
func TestFeatureRequestAcknowledged(t *testing.T) {
	leak.Check(t)

	t.Run("repeated once, then acknowledged", func(t *testing.T) {
		f := dial(t)
		out := f.featureGet(knxnetip.FeatureIndividualAddress)
		first := f.expectFeature()
		second := f.expectFeature() // the first is not acknowledged
		if first.Type != knxnetip.TunnellingFeatureGetType || second.Type != first.Type || second.Seq != first.Seq ||
			second.Feature != knxnetip.FeatureIndividualAddress || second.Channel != f.ch {
			t.Fatalf("request %+v repeated as %+v", first, second)
		}
		f.ack(second.Seq, knxnetip.StatusNoError)
		f.p.Send(f.client, &knxnetip.TunnellingFeature{Type: knxnetip.TunnellingFeatureResponseType, Channel: f.ch, Seq: 0,
			Feature: knxnetip.FeatureIndividualAddress, Value: []byte{0x11, 0xC8}})
		r := recv(t, out, "FeatureGet")
		if r.err != nil || !bytes.Equal(r.value, []byte{0x11, 0xC8}) {
			t.Fatalf("FeatureGet = % X, %v", r.value, r.err)
		}
		if n := f.m.get(func(m *metrics) int { return m.retransmits }); n != 1 {
			t.Errorf("%d repetitions counted, want 1", n)
		}
		// The following request carries the next sequence number.
		res := f.send(groupWrite(1))
		req := f.expectRequest()
		if req.Seq != first.Seq+1 {
			t.Fatalf("tunnelling request with sequence %d after a feature request with %d", req.Seq, first.Seq)
		}
		f.ack(req.Seq, knxnetip.StatusNoError)
		f.confirm(req, 1, false)
		if err := result(t, res); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("acknowledged at once", func(t *testing.T) {
		f := dial(t)
		out := make(chan error, 1)
		go func() { out <- f.c.FeatureSet(context.Background(), knxnetip.FeatureInfoServiceEnable, []byte{1}) }()
		req := f.expectFeature()
		if req.Type != knxnetip.TunnellingFeatureSetType || !bytes.Equal(req.Value, []byte{1}) {
			t.Fatalf("request %+v", req)
		}
		f.ack(req.Seq, knxnetip.StatusNoError)
		f.p.Send(f.client, &knxnetip.TunnellingFeature{Type: knxnetip.TunnellingFeatureResponseType, Channel: f.ch, Seq: 0,
			Feature: knxnetip.FeatureInfoServiceEnable, Value: []byte{1}})
		if err := recv(t, out, "FeatureSet"); err != nil {
			t.Fatal(err)
		}
		if n := f.m.get(func(m *metrics) int { return m.retransmits }); n != 0 {
			t.Errorf("%d repetitions counted, want none", n)
		}
	})

	t.Run("refused", func(t *testing.T) {
		f := dial(t)
		out := f.featureGet(knxnetip.FeatureIndividualAddress)
		req := f.expectFeature()
		f.ack(req.Seq, knxnetip.StatusSequenceNumber)
		r := recv(t, out, "FeatureGet")
		if st, ok := knxnetip.StatusOf(r.err); !ok || st != knxnetip.StatusSequenceNumber || !errors.Is(r.err, knx.ErrRejected) {
			t.Fatalf("FeatureGet = %v, want the status of the ACK", r.err)
		}
	})

	t.Run("never acknowledged", func(t *testing.T) {
		f := dial(t)
		out := f.featureGet(knxnetip.FeatureIndividualAddress)
		f.expectFeature()
		f.expectFeature()
		if r := recv(t, out, "FeatureGet"); !errors.Is(r.err, knx.ErrConnectionLost) {
			t.Fatalf("FeatureGet without an ACK = %v, want knx.ErrConnectionLost", r.err)
		}
		recv(t, f.c.Done(), "the Conn to close")
		if err := f.c.Err(); !errors.Is(err, knx.ErrConnectionLost) {
			t.Errorf("Err() = %v, want knx.ErrConnectionLost", err)
		}
	})

	t.Run("no response", func(t *testing.T) {
		f := dial(t)
		out := f.featureGet(knxnetip.FeatureIndividualAddress)
		req := f.expectFeature()
		f.ack(req.Seq, knxnetip.StatusNoError)
		if r := recv(t, out, "FeatureGet"); !errors.Is(r.err, knx.ErrTimeout) {
			t.Fatalf("FeatureGet without a response = %v, want knx.ErrTimeout", r.err)
		}
		// The connection stays up and the sequence number is consumed.
		res := f.send(groupWrite(1))
		next := f.expectRequest()
		if next.Seq != req.Seq+1 {
			t.Fatalf("sequence %d after an acknowledged feature request with %d", next.Seq, req.Seq)
		}
		f.ack(next.Seq, knxnetip.StatusNoError)
		f.confirm(next, 0, false)
		if err := result(t, res); err != nil {
			t.Fatal(err)
		}
	})
}

// L5: Dial with WithSecure is bounded by its context during the KNX IP
// Secure handshake too. A peer that takes the connection and stays silent
// makes Dial return the context's error, and nothing is left open.
func TestSecureDialContextEnds(t *testing.T) {
	leak.Check(t)
	cred, err := secure.NewCredentials(2, "pw", "dev")
	if err != nil {
		t.Fatal(err)
	}
	type dialResult struct {
		c   *tunnel.Conn
		err error
	}
	check := func(t *testing.T, r dialResult, want error, took time.Duration) {
		t.Helper()
		if r.c != nil {
			r.c.Close()
			t.Fatal("Dial returned a Conn")
		}
		if !errors.Is(r.err, want) {
			t.Fatalf("Dial = %v, want an error matching %v", r.err, want)
		}
		if took >= wait {
			t.Errorf("Dial took %v with a connect timeout of %v", took, wait)
		}
	}

	t.Run("TCP", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		accepted := make(chan net.Conn, 2)
		served := make(chan struct{})
		go func() {
			defer close(served)
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted <- c
			}
		}()
		before := openFDs()
		opts := []tunnel.Option{tunnel.WithSecure(cred), tunnel.WithConnectTimeout(wait)}

		short, cancelShort := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancelShort()
		start := time.Now()
		c, err := tunnel.Dial(short, ln.Addr().String(), opts...)
		check(t, dialResult{c, err}, context.DeadlineExceeded, time.Since(start))
		recv(t, accepted, "the first connection").Close()

		cx, cancel := context.WithCancel(context.Background())
		defer cancel()
		res := make(chan dialResult, 1)
		start = time.Now()
		go func() {
			c, err := tunnel.Dial(cx, ln.Addr().String(), opts...)
			res <- dialResult{c, err}
		}()
		peer := recv(t, accepted, "the second connection") // the client is connected and waits for the peer
		cancel()
		check(t, recv(t, res, "Dial to return"), context.Canceled, time.Since(start))
		peer.Close()
		if after := openFDs(); before >= 0 && after != before {
			t.Errorf("%d descriptors open after the failed Dials, %d before", after, before)
		}
		ln.Close()
		<-served
	})

	t.Run("UDP", func(t *testing.T) {
		p := fakeknx.Listen(t)
		before := openFDs()
		opts := []tunnel.Option{tunnel.WithSecure(cred), tunnel.WithUDP(), tunnel.WithConnectTimeout(wait)}

		short, cancelShort := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancelShort()
		start := time.Now()
		c, err := tunnel.Dial(short, p.String(), opts...)
		check(t, dialResult{c, err}, context.DeadlineExceeded, time.Since(start))
		fakeknx.Expect[*knxnetip.SessionRequest](p, wait)

		cx, cancel := context.WithCancel(context.Background())
		defer cancel()
		res := make(chan dialResult, 1)
		start = time.Now()
		go func() {
			c, err := tunnel.Dial(cx, p.String(), opts...)
			res <- dialResult{c, err}
		}()
		fakeknx.Expect[*knxnetip.SessionRequest](p, wait) // the client waits for the SESSION_RESPONSE
		cancel()
		check(t, recv(t, res, "Dial to return"), context.Canceled, time.Since(start))
		if after := openFDs(); before >= 0 && after != before {
			t.Errorf("%d descriptors open after the failed Dials, %d before", after, before)
		}
	})
}

// L14: a Dial that fails leaves no socket open.
func TestDialFailureReleasesSocket(t *testing.T) {
	leak.Check(t)
	cred, err := secure.NewCredentials(2, "pw", "dev")
	if err != nil {
		t.Fatal(err)
	}
	refuse := func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		switch d.Msg.(type) {
		case *knxnetip.ConnectRequest:
			p.Send(d.From, &knxnetip.ConnectResponse{Status: knxnetip.StatusNoMoreConnections})
		case *knxnetip.SessionRequest:
			p.Send(d.From, &knxnetip.SessionStatus{Status: knxnetip.SessionAuthFailed})
		}
		return true
	}
	wrongCRD := func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if _, ok := d.Msg.(*knxnetip.ConnectRequest); ok {
			p.Send(d.From, &knxnetip.ConnectResponse{Channel: 7, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.DeviceManagementConnection}})
		}
		return true
	}
	silent := func(*fakeknx.Peer, fakeknx.Datagram) bool { return true }
	for name, tc := range map[string]struct {
		answer fakeknx.Handler
		opts   []tunnel.Option
		want   error
	}{
		"refused":                  {refuse, nil, knx.ErrBusy},
		"a CRD of another type":    {wrongCRD, nil, knx.ErrMalformed},
		"no response":              {silent, []tunnel.Option{tunnel.WithConnectTimeout(20 * time.Millisecond)}, knx.ErrTimeout},
		"secure session refused":   {refuse, []tunnel.Option{tunnel.WithSecure(cred), tunnel.WithUDP()}, knx.ErrRejected},
		"secure session, silence":  {silent, []tunnel.Option{tunnel.WithSecure(cred), tunnel.WithUDP(), tunnel.WithConnectTimeout(20 * time.Millisecond)}, knx.ErrTimeout},
		"conflicting options":      {silent, []tunnel.Option{tunnel.WithTCP(), tunnel.WithUDP()}, knx.ErrInvalidOption},
		"no listener on the port":  {nil, []tunnel.Option{tunnel.WithTCP(), tunnel.WithConnectTimeout(wait)}, nil},
		"an address without route": {silent, []tunnel.Option{tunnel.WithLocalAddr("192.0.2.1:0")}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			p := fakeknx.Listen(t)
			if tc.answer != nil {
				p.Handle(tc.answer)
			}
			before := openFDs()
			c, err := tunnel.Dial(ctx(t), p.String(), tc.opts...)
			if c != nil {
				c.Close()
				t.Fatal("Dial returned a Conn")
			}
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("Dial = %v, want an error matching %v", err, tc.want)
			}
			if after := openFDs(); before >= 0 && after != before {
				t.Errorf("%d descriptors open after the failed Dial, %d before", after, before)
			}
		})
	}
}

// L2: Close from several goroutines, with a Send and a Receive in flight:
// every Close returns, the calls end with knx.ErrClosed, one
// DISCONNECT_REQUEST is sent and the socket is released once.
func TestCloseConcurrently(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	var disconnects atomic.Int32
	p.Handle(func(_ *fakeknx.Peer, d fakeknx.Datagram) bool {
		if _, ok := d.Msg.(*knxnetip.DisconnectRequest); ok {
			disconnects.Add(1)
		}
		return false
	})
	p.Handle(fakeknx.AnswerDisconnect)
	before := openFDs()
	f := dialPeer(t, p, tunnel.WithRequestTimeout(time.Minute))
	sent := f.send(groupWrite(1))
	f.expectRequest() // Send waits for its ACK
	rctx := newWaitCtx(context.Background())
	received := make(chan error, 1)
	go func() { _, err := f.c.Receive(rctx); received <- err }()
	recv(t, rctx.waiting, "Receive to block")

	const closers = 8
	start := make(chan struct{})
	errs := make(chan error, closers)
	for range closers {
		go func() {
			<-start
			errs <- f.c.Close()
		}()
	}
	close(start)
	for range closers {
		if err := recv(t, errs, "a Close to return"); err != nil {
			t.Errorf("Close = %v", err)
		}
	}
	if err := result(t, sent); !errors.Is(err, knx.ErrClosed) {
		t.Errorf("Send at Close = %v, want knx.ErrClosed", err)
	}
	if err := result(t, received); !errors.Is(err, knx.ErrClosed) {
		t.Errorf("Receive at Close = %v, want knx.ErrClosed", err)
	}
	if f.c.State() != knx.StateClosed || f.c.Err() != nil {
		t.Errorf("state %s, Err %v after Close", f.c.State(), f.c.Err())
	}
	// Close returned after the answer to its DISCONNECT_REQUEST, so the
	// fake server has counted every one that was sent.
	if n := disconnects.Load(); n != 1 {
		t.Errorf("%d DISCONNECT_REQUESTs, want 1", n)
	}
	if after := openFDs(); before >= 0 && after != before {
		t.Errorf("%d descriptors open after Close, %d before Dial", after, before)
	}
}

// reconnected dials with reconnection and reports each time the Conn is
// connected.
func reconnected(t *testing.T, p *fakeknx.Peer, opts ...tunnel.Option) (*fixture, <-chan struct{}) {
	t.Helper()
	connected := make(chan struct{}, 8)
	f := dialPeer(t, p, append([]tunnel.Option{
		tunnel.WithReconnect(time.Millisecond, time.Millisecond), tunnel.WithConfirm(false, 0),
		tunnel.WithStateHandler(func(s knx.State, _ error) {
			if s == knx.StateConnected {
				connected <- struct{}{}
			}
		})}, opts...)...)
	recv(t, connected, "the first connection")
	return f, connected
}

// again lets the server end the connection and accept the reconnection on
// the same channel, as a server does for a client that comes back from the
// same endpoints.
func (f *fixture) again(connected <-chan struct{}) {
	f.t.Helper()
	f.p.Send(f.client, &knxnetip.DisconnectRequest{Channel: f.ch, Control: f.p.HPAI()})
	req, _ := fakeknx.Expect[*knxnetip.ConnectRequest](f.p, wait)
	f.p.Send(req.Control.Addr, &knxnetip.ConnectResponse{Channel: f.ch, Data: f.p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
	recv(f.t, connected, "the reconnection")
}

// L8: after a reconnection the server may give the same channel, and the
// sequence numbers start at 0 again. An acknowledgement of the earlier
// connection that is already there completes no request of the new one.
func TestAckOfEarlierConnection(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	f, connected := reconnected(t, p)
	res := f.send(groupWrite(1))
	old := f.expectRequest()
	f.ack(old.Seq, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
	f.again(connected)
	if f.c.Channel() != f.ch {
		t.Fatalf("channel %d after the reconnection, want %d again", f.c.Channel(), f.ch)
	}
	// The acknowledgement of the earlier connection, repeated late: same
	// channel, same sequence number as the first request of the new one.
	// The marker after it tells that the reader has taken it.
	f.ack(old.Seq, knxnetip.StatusNoError)
	f.inbound(0, indication(9))
	receive(t, f.c)
	res = f.send(groupWrite(2))
	first := f.expectRequest()
	if first.Seq != old.Seq {
		t.Fatalf("sequence %d on the new connection, want %d again", first.Seq, old.Seq)
	}
	// Not acknowledged: the client repeats it, which it would not do had
	// the earlier acknowledgement completed the request.
	second := f.expectRequest()
	if second.Seq != first.Seq || value(t, second) != 2 {
		t.Fatalf("repetition %+v", second)
	}
	f.ack(second.Seq, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
	if n := f.m.get(func(m *metrics) int { return m.retransmits }); n != 1 {
		t.Errorf("%d repetitions, want 1", n)
	}
}

// L8: a request whose caller left before its acknowledgement belongs to
// the connection it was sent on. After a reconnection it is forgotten:
// the first Send on the new connection goes out at once, with sequence 0.
func TestUnacknowledgedRequestOfEarlierConnection(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	f, connected := reconnected(t, p, tunnel.WithRequestTimeout(time.Minute))
	cx, cancel := context.WithCancel(context.Background())
	res := f.sendCtx(cx, groupWrite(1))
	f.expectRequest()
	cancel()
	if err := result(t, res); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Send = %v", err)
	}
	f.again(connected)
	res = f.send(groupWrite(2))
	req := f.expectRequest()
	if req.Seq != 0 || value(t, req) != 2 {
		t.Fatalf("first request of the new connection: sequence %d, value %d", req.Seq, value(t, req))
	}
	f.ack(req.Seq, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
}

// The waits between reconnection attempts are drawn from the upper half
// of a backoff that starts at the minimum and doubles up to the maximum.
func TestReconnectWaitsAreJittered(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	draws := make(chan time.Duration, 64)
	source := func(n int64) int64 {
		select {
		case draws <- time.Duration(n):
		default:
		}
		return 0 // the shortest wait of each interval
	}
	const minimum, maximum = 4 * time.Millisecond, 20 * time.Millisecond
	f := dialPeer(t, p, tunnel.WithReconnect(minimum, maximum), tunnel.WithJitterSource(source))
	// Every reconnection is refused, so the client keeps trying.
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if _, ok := d.Msg.(*knxnetip.ConnectRequest); ok {
			p.Send(d.From, &knxnetip.ConnectResponse{Status: knxnetip.StatusNoMoreConnections})
			return true
		}
		return false
	})
	f.p.Send(f.client, &knxnetip.DisconnectRequest{Channel: f.ch, Control: f.p.HPAI()})
	// The source is asked for a value in [0, backoff/2]: the wait is
	// backoff/2 plus that value.
	for i, backoff := range []time.Duration{minimum, 2 * minimum, 4 * minimum, maximum, maximum} {
		if got := recv(t, draws, "a reconnection wait to be drawn"); got != backoff/2 {
			t.Fatalf("wait %d drawn from [0, %v], want [0, %v] for a backoff of %v", i+1, got, backoff/2, backoff)
		}
	}
	f.c.Close()
}
