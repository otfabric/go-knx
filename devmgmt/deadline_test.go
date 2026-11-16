// SPDX-License-Identifier: MIT

package devmgmt_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/devmgmt"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
)

// steppingCtx is a context that reports every wait a call starts on it
// and that the test ends: with context.DeadlineExceeded (expire) or
// context.Canceled (cancel).
type steppingCtx struct {
	context.Context
	steps chan struct{}
	done  chan struct{}
	once  sync.Once
	err   error
}

func newSteppingCtx() *steppingCtx {
	return &steppingCtx{Context: context.Background(), steps: make(chan struct{}, 16), done: make(chan struct{})}
}

func (s *steppingCtx) Done() <-chan struct{} {
	select {
	case s.steps <- struct{}{}:
	default:
	}
	return s.done
}

func (s *steppingCtx) Err() error {
	select {
	case <-s.done:
		return s.err
	default:
		return nil
	}
}

func (s *steppingCtx) Deadline() (time.Time, bool) { return time.Now().Add(time.Hour), true }

func (s *steppingCtx) end(err error) { s.once.Do(func() { s.err = err; close(s.done) }) }

// ERR-R01: PropRead and PropWrite whose deadline passes while they wait
// for the confirmation return an error matching knx.ErrTimeout and
// context.DeadlineExceeded whose message names the timeout once and the
// request; cancelled, they match context.Canceled only.
func TestPropDeadlineIsTimeout(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		switch m := d.Msg.(type) {
		case *knxnetip.ConnectRequest:
			p.Send(m.Control.Addr, &knxnetip.ConnectResponse{Channel: 3, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.DeviceManagementConnection}})
		case *knxnetip.DeviceConfigurationRequest:
			// Acknowledged, never confirmed.
			p.Send(d.From, &knxnetip.DeviceConfigurationAck{Channel: m.Channel, Seq: m.Seq})
		default:
			return fakeknx.AnswerConnectionState(p, d) || fakeknx.AnswerDisconnect(p, d)
		}
		return true
	})
	dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := devmgmt.Dial(dctx, p.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, call := range []struct {
		name string
		do   func(context.Context) error
		msg  string // the message at the deadline
	}{
		{"PropRead", func(cx context.Context) error {
			_, err := c.PropRead(cx, devmgmt.ObjectDevice, 1, devmgmt.PIDSerialNumber, 1, 1)
			return err
		}, "knx: timeout: devmgmt: no M_PropRead.con for object 0x0000 property 11: context deadline exceeded"},
		{"PropWrite", func(cx context.Context) error {
			return c.PropWrite(cx, devmgmt.ObjectDevice, 1, devmgmt.PIDSerialNumber, 1, 1, []byte{0, 0xFA, 0, 0, 0, 1})
		}, "knx: timeout: devmgmt: no M_PropWrite.con for object 0x0000 property 11: context deadline exceeded"},
	} {
		for _, end := range []error{context.DeadlineExceeded, context.Canceled} {
			t.Run(call.name+", "+end.Error(), func(t *testing.T) {
				sctx := newSteppingCtx()
				res := make(chan error, 1)
				go func() { res <- call.do(sctx) }()
				// Its acknowledgement, then the confirmation.
				for _, what := range []string{"the acknowledgement", "the confirmation"} {
					select {
					case <-sctx.steps:
					case <-time.After(wait):
						t.Fatalf("timed out waiting for %s to wait for %s", call.name, what)
					}
				}
				sctx.end(end)
				var err error
				select {
				case err = <-res:
				case <-time.After(wait):
					t.Fatalf("%s did not return", call.name)
				}
				if end == context.Canceled {
					if !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("cancelled %s = %v, want an error matching context.Canceled only", call.name, err)
					}
					return
				}
				if !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("%s whose deadline passed = %v, want an error matching knx.ErrTimeout and context.DeadlineExceeded", call.name, err)
				}
				if err.Error() != call.msg {
					t.Fatalf("%s whose deadline passed: message %q, want %q", call.name, err.Error(), call.msg)
				}
			})
		}
	}
}
