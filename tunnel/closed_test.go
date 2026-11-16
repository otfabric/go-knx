// SPDX-License-Identifier: MIT

package tunnel_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/tunnel"
)

// Close contract 3: Send, FeatureGet and FeatureSet after Close return
// knx.ErrClosed and write nothing.
func TestCallsAfterClose(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"Send": func() error { return f.c.Send(ctx(t), groupWrite(1)) },
		"FeatureGet": func() error {
			_, err := f.c.FeatureGet(ctx(t), knxnetip.FeatureIndividualAddress)
			return err
		},
		"FeatureSet": func() error {
			return f.c.FeatureSet(ctx(t), knxnetip.FeatureInfoServiceEnable, []byte{1})
		},
	} {
		if err := call(); !errors.Is(err, knx.ErrClosed) || errors.Is(err, knx.ErrConnectionLost) {
			t.Errorf("%s after Close = %v, want knx.ErrClosed", name, err)
		}
	}
	if d, ok := f.p.Next(50 * time.Millisecond); ok {
		t.Fatalf("%s written after Close", d.Msg.Service())
	}
}

// expiringCtx is a context whose deadline the test ends: it reports every
// wait a call starts on it, and expire ends it with
// context.DeadlineExceeded.
type expiringCtx struct {
	context.Context
	steps chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newExpiringCtx() *expiringCtx {
	return &expiringCtx{Context: context.Background(), steps: make(chan struct{}, 16), done: make(chan struct{})}
}

func (e *expiringCtx) Done() <-chan struct{} {
	select {
	case e.steps <- struct{}{}:
	default:
	}
	return e.done
}

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

// ERR-R01: a Send that ends at its context's deadline returns an error
// matching knx.ErrTimeout and context.DeadlineExceeded, in each of its
// waits: for its turn, for the acknowledgement of an earlier request whose
// caller left, for its own TUNNELLING_ACK and for the L_Data.con. A
// cancelled Send matches context.Canceled only.
func TestSendDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	timeout := func(t *testing.T, err error, wait string) {
		t.Helper()
		if !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Send whose deadline passed while it waited for %s = %v, want an error matching knx.ErrTimeout and context.DeadlineExceeded", wait, err)
		}
	}

	t.Run("its acknowledgement", func(t *testing.T) {
		f := dial(t, tunnel.WithRequestTimeout(time.Minute))
		dctx := newExpiringCtx()
		res := f.sendCtx(dctx, groupWrite(1))
		f.expectRequest()
		recv(t, dctx.steps, "Send to wait for the ACK")
		dctx.expire()
		timeout(t, result(t, res), "its TUNNELLING_ACK")
	})

	t.Run("its turn", func(t *testing.T) {
		f := dial(t, tunnel.WithRequestTimeout(time.Minute), tunnel.WithConfirm(false, 0))
		first := f.send(groupWrite(1))
		req := f.expectRequest()
		dctx := newExpiringCtx()
		res := f.sendCtx(dctx, groupWrite(2))
		recv(t, dctx.steps, "the second Send to wait for its turn")
		dctx.expire()
		timeout(t, result(t, res), "its turn")
		f.ack(req.Seq, knxnetip.StatusNoError)
		if err := result(t, first); err != nil {
			t.Fatalf("first Send = %v", err)
		}
	})

	t.Run("the acknowledgement of an earlier request", func(t *testing.T) {
		f := dial(t, tunnel.WithRequestTimeout(time.Minute), tunnel.WithConfirm(false, 0))
		cctx, cancel := context.WithCancel(context.Background())
		steps := newStepCtx(cctx)
		left := f.sendCtx(steps, groupWrite(1))
		req := f.expectRequest()
		recv(t, steps.steps, "the first Send to wait for its ACK")
		cancel()
		if err := result(t, left); !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) {
			t.Fatalf("cancelled Send = %v, want context.Canceled only", err)
		}
		dctx := newExpiringCtx()
		res := f.sendCtx(dctx, groupWrite(2))
		recv(t, dctx.steps, "the next Send to wait for the earlier ACK")
		dctx.expire()
		timeout(t, result(t, res), "the ACK of the earlier request")
		f.ack(req.Seq, knxnetip.StatusNoError)
	})

	t.Run("the confirmation", func(t *testing.T) {
		f := dial(t, tunnel.WithConfirm(true, time.Minute))
		dctx := newExpiringCtx()
		res := f.sendCtx(dctx, groupWrite(1))
		req := f.expectRequest()
		recv(t, dctx.steps, "Send to wait for the ACK")
		f.ack(req.Seq, knxnetip.StatusNoError)
		recv(t, dctx.steps, "Send to wait for the L_Data.con")
		dctx.expire()
		timeout(t, result(t, res), "the L_Data.con")
	})

	t.Run("a real deadline", func(t *testing.T) {
		f := dial(t, tunnel.WithRequestTimeout(time.Minute))
		dctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		res := f.sendCtx(dctx, groupWrite(1))
		f.expectRequest()
		timeout(t, result(t, res), "its TUNNELLING_ACK")
	})
}

// L16: a reconnection whose CONNECT_RESPONSE comes while Close runs does
// not leave its channel at the server: Close waits for the answer to the
// CONNECT_REQUEST it interrupted, for at most a second, and disconnects
// the channel the answer opened.
func TestCloseReleasesChannelOfReconnection(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	disconnected := make(chan uint8, 4)
	p.Handle(func(_ *fakeknx.Peer, d fakeknx.Datagram) bool {
		if m, ok := d.Msg.(*knxnetip.DisconnectRequest); ok {
			disconnected <- m.Channel
		}
		return false
	})
	p.Handle(fakeknx.AnswerDisconnect)
	f := dialPeer(t, p, tunnel.WithReconnect(time.Millisecond, time.Millisecond), tunnel.WithConnectTimeout(time.Minute))
	f.p.Send(f.client, &knxnetip.DisconnectRequest{Channel: f.ch, Control: f.p.HPAI()})
	req, _ := fakeknx.Expect[*knxnetip.ConnectRequest](p, wait) // not answered yet
	closed := make(chan struct{})
	go func() { f.c.Close(); close(closed) }()
	recv(t, tunnel.Closing(f.c), "Close to begin")
	p.Send(req.Control.Addr, &knxnetip.ConnectResponse{Channel: 9, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
	if ch := recv(t, disconnected, "a DISCONNECT_REQUEST for the channel of the reconnection"); ch != 9 {
		t.Fatalf("DISCONNECT_REQUEST for channel %d, want 9", ch)
	}
	recv(t, closed, "Close to return")
	if s := f.c.State(); s != knx.StateClosed {
		t.Fatalf("state %s after Close", s)
	}
}
