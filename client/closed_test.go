// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/internal/leak"
)

// deviceCalls are the requests of a Device.
var deviceCalls = map[string]func(context.Context, *client.Device) error{
	"PropertyRead": func(ctx context.Context, d *client.Device) error {
		_, err := d.PropertyRead(ctx, 0, 11, 1, 1)
		return err
	},
	"PropertyWrite": func(ctx context.Context, d *client.Device) error {
		_, err := d.PropertyWrite(ctx, 0, 76, 1, 1, []byte{'x'})
		return err
	},
	"PropertyElements": func(ctx context.Context, d *client.Device) error {
		_, err := d.PropertyElements(ctx, 0, 71)
		return err
	},
	"PropertyDescription": func(ctx context.Context, d *client.Device) error {
		_, err := d.PropertyDescription(ctx, 0, 11, 0)
		return err
	},
	"DescriptorRead": func(ctx context.Context, d *client.Device) error {
		_, err := d.DescriptorRead(ctx)
		return err
	},
}

func sentFrames(l *link) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sent)
}

// Close contract 3 for a Device: a request after Device.Close or after
// Client.Close returns knx.ErrClosed at once and sends nothing.
func TestDeviceRequestsAfterClose(t *testing.T) {
	leak.Check(t)
	for name, call := range deviceCalls {
		for _, closer := range []string{"Device", "Client"} {
			t.Run(name+" after "+closer+".Close", func(t *testing.T) {
				l := newLink()
				c := client.New(l, client.WithSource(src))
				defer c.Close()
				d := c.Device(serverAddress)
				if closer == "Device" {
					if err := d.Close(); err != nil {
						t.Fatal(err)
					}
				} else if err := c.Close(); err != nil {
					t.Fatal(err)
				}
				// A short deadline, so that a request that went out ends.
				cx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()
				if err := call(cx, d); !errors.Is(err, knx.ErrClosed) {
					t.Fatalf("%s after %s.Close = %v, want knx.ErrClosed", name, closer, err)
				}
				if n := sentFrames(l); n != 0 {
					t.Fatalf("%d frames sent after %s.Close, want 0", n, closer)
				}
			})
		}
	}
}

// Close contract 2 and L3 for a Device: a request that waits for its
// answer, or for its turn, when the Device or the client closes returns
// knx.ErrClosed; Close of a Device in a connection still ends the
// connection.
func TestDeviceRequestEndsWithClose(t *testing.T) {
	leak.Check(t)
	for _, closer := range []string{"Device", "Client"} {
		t.Run("connectionless, "+closer+".Close", func(t *testing.T) {
			l := newLink()
			c := client.New(l, client.WithSource(src))
			defer c.Close()
			d := c.Device(serverAddress)
			first, second := make(chan error, 1), make(chan error, 1)
			go func() { _, err := d.DescriptorRead(ctx(t)); first <- err }()
			waitSent(t, l, 1) // the first request waits for its answer
			wctx := newWaitCtx(ctx(t))
			go func() { _, err := d.DescriptorRead(wctx); second <- err }()
			recv(t, wctx.waiting, "the second request to wait for its turn")
			closed := make(chan error, 1)
			go func() {
				if closer == "Device" {
					closed <- d.Close()
				} else {
					closed <- c.Close()
				}
			}()
			for _, res := range []chan error{first, second} {
				if err := recv(t, res, "a request to return at "+closer+".Close"); !errors.Is(err, knx.ErrClosed) {
					t.Errorf("request at %s.Close = %v, want knx.ErrClosed", closer, err)
				}
			}
			if err := recv(t, closed, closer+".Close to return"); err != nil {
				t.Errorf("%s.Close = %v", closer, err)
			}
			if n := sentFrames(l); n != 1 {
				t.Errorf("%d frames sent, want 1: the request that waited", n)
			}
		})
	}
	t.Run("in a connection, Device.Close", func(t *testing.T) {
		l := newLink()
		c := client.New(l, client.WithSource(src))
		defer c.Close()
		d := c.Device(serverAddress, client.Connected())
		res := make(chan error, 1)
		go func() { _, err := d.DescriptorRead(ctx(t)); res <- err }()
		waitSent(t, l, 2) // T_Connect and the request, which is not acknowledged
		closed := make(chan error, 1)
		go func() { closed <- d.Close() }()
		if err := recv(t, res, "the request to return at Device.Close"); !errors.Is(err, knx.ErrClosed) {
			t.Errorf("request at Device.Close = %v, want knx.ErrClosed", err)
		}
		if err := recv(t, closed, "Device.Close to return"); err != nil {
			t.Errorf("Device.Close = %v", err)
		}
		if tp, err := apdu.Parse(l.last(t).TPDU); err != nil || tp.TPCI.Kind != apdu.TDisconnect {
			t.Errorf("last frame sent %+v, want T_Disconnect", tp)
		}
	})
}

// ERR-R01: a GroupRead that ends at its deadline returns an error matching
// knx.ErrTimeout and context.DeadlineExceeded, while it waits for a
// response and while its request waits for the link. A cancelled one
// matches context.Canceled only.
func TestGroupReadDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	c, _ := newClient(t)
	cx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.GroupRead(cx, g1); !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GroupRead without a response = %v, want an error matching knx.ErrTimeout and context.DeadlineExceeded", err)
	}

	bl := &blockingLink{link: newLink(), sending: make(chan struct{}, 1)}
	bc := client.New(bl)
	defer bc.Close()
	cx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := bc.GroupRead(cx, g1); !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GroupRead whose request the link did not take = %v, want an error matching knx.ErrTimeout and context.DeadlineExceeded", err)
	}

	cx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := bc.GroupRead(cx, g1); !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("cancelled GroupRead = %v, want context.Canceled only", err)
	}
}

// waitCtx is a context that reports when a call starts to wait on it.
type waitCtx struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func newWaitCtx(parent context.Context) *waitCtx {
	return &waitCtx{Context: parent, waiting: make(chan struct{})}
}

func (w *waitCtx) Done() <-chan struct{} {
	w.once.Do(func() { close(w.waiting) })
	return w.Context.Done()
}
