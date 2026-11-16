// SPDX-License-Identifier: MIT

package tunnel_test

import (
	"context"
	"errors"
	"net"
	"strings"
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

// isTimeout fails the test unless err matches knx.ErrTimeout and
// context.DeadlineExceeded, and its message names the package once.
func isTimeout(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%s = %v, want an error matching knx.ErrTimeout and context.DeadlineExceeded", what, err)
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "knx: timeout: tunnel: ") || strings.Contains(msg, "tunnel: tunnel: ") {
		t.Fatalf("%s: message %q, want it to start with \"knx: timeout: tunnel: \" and name the package once", what, msg)
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

// ERR-R01: FeatureGet and FeatureSet that end at their context's deadline
// return an error matching knx.ErrTimeout and context.DeadlineExceeded,
// whether they waited for their turn, for the TUNNELLING_ACK or for the
// TUNNELLING_FEATURE_RESPONSE. A cancelled one matches context.Canceled
// only.
func TestFeatureDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	for name, call := range map[string]func(*tunnel.Conn, context.Context) <-chan error{
		"FeatureGet": func(c *tunnel.Conn, cx context.Context) <-chan error {
			ch := make(chan error, 1)
			go func() { _, err := c.FeatureGet(cx, knxnetip.FeatureIndividualAddress); ch <- err }()
			return ch
		},
		"FeatureSet": func(c *tunnel.Conn, cx context.Context) <-chan error {
			ch := make(chan error, 1)
			go func() { ch <- c.FeatureSet(cx, knxnetip.FeatureInfoServiceEnable, []byte{1}) }()
			return ch
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Run("its acknowledgement", func(t *testing.T) {
				f := dial(t, tunnel.WithRequestTimeout(time.Minute))
				dctx := newExpiringCtx()
				res := call(f.c, dctx)
				f.expectFeature()
				recv(t, dctx.steps, name+" to wait for the ACK")
				dctx.expire()
				isTimeout(t, result(t, res), name+" whose deadline passed while it waited for its TUNNELLING_ACK")
			})

			t.Run("the response", func(t *testing.T) {
				f := dial(t, tunnel.WithRequestTimeout(time.Minute), tunnel.WithConfirm(true, time.Minute))
				dctx := newExpiringCtx()
				res := call(f.c, dctx)
				req := f.expectFeature()
				recv(t, dctx.steps, name+" to wait for the ACK")
				f.ack(req.Seq, knxnetip.StatusNoError)
				recv(t, dctx.steps, name+" to wait for the response")
				dctx.expire()
				isTimeout(t, result(t, res), name+" whose deadline passed while it waited for the response")
			})

			t.Run("its turn", func(t *testing.T) {
				f := dial(t, tunnel.WithRequestTimeout(time.Minute), tunnel.WithConfirm(false, 0))
				first := f.send(groupWrite(1))
				req := f.expectRequest()
				dctx := newExpiringCtx()
				res := call(f.c, dctx)
				recv(t, dctx.steps, name+" to wait for its turn")
				dctx.expire()
				isTimeout(t, result(t, res), name+" whose deadline passed while it waited for its turn")
				f.ack(req.Seq, knxnetip.StatusNoError)
				if err := result(t, first); err != nil {
					t.Fatalf("first Send = %v", err)
				}
			})

			t.Run("a real deadline", func(t *testing.T) {
				f := dial(t, tunnel.WithRequestTimeout(time.Minute))
				dctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				res := call(f.c, dctx)
				f.expectFeature()
				isTimeout(t, result(t, res), name+" with a deadline of 20 ms")
			})

			t.Run("cancelled", func(t *testing.T) {
				f := dial(t, tunnel.WithRequestTimeout(time.Minute))
				cctx, cancel := context.WithCancel(context.Background())
				steps := newStepCtx(cctx)
				res := call(f.c, steps)
				f.expectFeature()
				recv(t, steps.steps, name+" to wait for the ACK")
				cancel()
				isCanceled(t, result(t, res), "cancelled "+name)
			})
		})
	}
}

// ERR-R01: a Dial whose context deadline passes returns an error matching
// knx.ErrTimeout and context.DeadlineExceeded, whether it waited for the
// CONNECT_RESPONSE, for the dialer of WithDialer or for the KNX IP Secure
// handshake over TCP or UDP. A cancelled Dial matches context.Canceled
// only, and the connect timeout of the library knx.ErrTimeout only.
func TestDialDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	cred, err := secure.NewCredentials(2, "pw", "dev")
	if err != nil {
		t.Fatal(err)
	}
	short := func(t *testing.T) context.Context {
		cx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		t.Cleanup(cancel)
		return cx
	}
	dialErr := func(cx context.Context, addr string, opts ...tunnel.Option) error {
		c, err := tunnel.Dial(cx, addr, append([]tunnel.Option{tunnel.WithConnectTimeout(time.Minute)}, opts...)...)
		if c != nil {
			c.Close()
			return errors.New("Dial returned a Conn")
		}
		return err
	}

	t.Run("CONNECT_RESPONSE", func(t *testing.T) {
		p := fakeknx.Listen(t)
		isTimeout(t, dialErr(short(t), p.String()), "Dial whose deadline passed while it waited for the CONNECT_RESPONSE")
	})

	t.Run("the dialer", func(t *testing.T) {
		dialer := func(cx context.Context, _, _ string) (net.Conn, error) {
			<-cx.Done()
			return nil, cx.Err()
		}
		isTimeout(t, dialErr(short(t), "127.0.0.1:3671", tunnel.WithTCP(), tunnel.WithDialer(dialer)), "Dial whose deadline passed in the dialer")
	})

	t.Run("the secure handshake over TCP", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		accepted := make(chan net.Conn, 1)
		go func() {
			if c, err := ln.Accept(); err == nil {
				accepted <- c
			}
			close(accepted)
		}()
		isTimeout(t, dialErr(short(t), ln.Addr().String(), tunnel.WithSecure(cred)), "Dial whose deadline passed in the secure handshake over TCP")
		ln.Close()
		if c := recv(t, accepted, "the connection"); c != nil {
			c.Close()
		}
	})

	t.Run("the secure handshake over UDP", func(t *testing.T) {
		p := fakeknx.Listen(t)
		isTimeout(t, dialErr(short(t), p.String(), tunnel.WithSecure(cred), tunnel.WithUDP()), "Dial whose deadline passed in the secure handshake over UDP")
	})

	t.Run("cancelled", func(t *testing.T) {
		p := fakeknx.Listen(t)
		cx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			fakeknx.Expect[*knxnetip.ConnectRequest](p, wait)
			cancel()
		}()
		isCanceled(t, dialErr(cx, p.String()), "cancelled Dial")
	})

	t.Run("the connect timeout", func(t *testing.T) {
		p := fakeknx.Listen(t)
		_, err := tunnel.Dial(ctx(t), p.String(), tunnel.WithConnectTimeout(30*time.Millisecond))
		if !errors.Is(err, knx.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dial at the end of its connect timeout = %v, want an error matching knx.ErrTimeout only", err)
		}
	})
}

// ERR-R01: a Receive that ends at its context's deadline returns an error
// matching knx.ErrTimeout and context.DeadlineExceeded, whether the
// deadline had passed when it was called or passed while it waited for a
// frame. A cancelled Receive matches context.Canceled only. A frame
// already queued is returned whatever the state of the context.
func TestReceiveDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	passed := func(t *testing.T) context.Context {
		cx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		t.Cleanup(cancel)
		return cx
	}
	cancelled := func(*testing.T) context.Context {
		cx, cancel := context.WithCancel(context.Background())
		cancel()
		return cx
	}
	receiveErr := func(c *tunnel.Conn, cx context.Context) <-chan error {
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
		err   func(t *testing.T, f *fixture) error
		check func(t *testing.T, err error, what string)
	}{
		{"the deadline had passed", func(t *testing.T, f *fixture) error {
			return result(t, receiveErr(f.c, passed(t)))
		}, isTimeout},
		{"the deadline passes while it waits", func(t *testing.T, f *fixture) error {
			dctx := newExpiringCtx()
			res := receiveErr(f.c, dctx)
			recv(t, dctx.steps, "Receive to wait for a frame")
			dctx.expire()
			return result(t, res)
		}, isTimeout},
		{"cancelled before", func(t *testing.T, f *fixture) error {
			return result(t, receiveErr(f.c, cancelled(t)))
		}, isCanceled},
		{"cancelled while it waits", func(t *testing.T, f *fixture) error {
			cx, cancel := context.WithCancel(context.Background())
			defer cancel()
			steps := newStepCtx(cx)
			res := receiveErr(f.c, steps)
			recv(t, steps.steps, "Receive to wait for a frame")
			cancel()
			return result(t, res)
		}, isCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dial(t)
			tc.check(t, tc.err(t, f), "Receive, "+tc.name)
		})
	}

	t.Run("a queued frame", func(t *testing.T) {
		f := dial(t)
		// The connection handles one datagram after the other: once the
		// third is acknowledged, the first two frames are queued.
		for seq := range uint8(3) {
			f.inbound(seq, indication(seq+1))
		}
		for range 3 {
			fakeknx.Expect[*knxnetip.TunnellingAck](f.p, wait)
		}
		for i, cx := range []context.Context{passed(t), cancelled(t)} {
			fr, err := f.c.Receive(cx)
			ld, ok := fr.(*cemi.LData)
			if !ok || err != nil || ld.TPDU[len(ld.TPDU)-1] != byte(i+1) {
				t.Fatalf("Receive with an ended context and frame %d queued = %v, %v, want that frame", i+1, fr, err)
			}
		}
	})
}
