// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/knxnetip"
)

// closedTransport fails every write as a socket closed under the writer.
type closedTransport struct{ stream_ bool }

func (closedTransport) writeTo([]byte, netip.AddrPort) error { return net.ErrClosed }
func (closedTransport) writeContext(context.Context, []byte, netip.AddrPort) error {
	return net.ErrClosed
}
func (closedTransport) readFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, net.ErrClosed
}
func (closedTransport) close() error                { return nil }
func (closedTransport) localAddr() net.Addr         { return &net.UDPAddr{} }
func (closedTransport) setDeadline(time.Time) error { return nil }
func (t closedTransport) stream() bool              { return t.stream_ }

func connectedConn(stream bool) *Conn {
	return &Conn{
		o: defaultOptions(), tr: closedTransport{stream_: stream},
		state: knx.StateConnected, channel: 1, gen: 1,
		dataEP: netip.MustParseAddrPort("127.0.0.1:3671"),
		ackCh:  make(chan *knxnetip.TunnellingAck, 1),
		lost:   make(chan lostEvent, 1), closing: make(chan struct{}),
	}
}

// A write that fails because the socket was closed under Send used to
// return the bare net.ErrClosed over UDP, which matches neither
// knx.ErrClosed nor knx.ErrConnectionLost.
func TestSendWriteErrorContract(t *testing.T) {
	frame := cemi.NewGroupFrame(cemi.LDataReq, 0, 1, knx.PriorityLow, []byte{0x00, 0x81})
	for _, c := range []struct {
		name     string
		stream   bool
		closed   bool  // Close or a loss shut the Conn down first
		cause    error // its cause; nil for Close
		want     error
		wantLost bool // the loss is signalled to the supervisor
	}{
		{"UDP, still up", false, false, nil, knx.ErrConnectionLost, true},
		{"TCP, still up", true, false, nil, knx.ErrConnectionLost, true},
		{"UDP, closed by Close", false, true, nil, knx.ErrClosed, false},
		{"TCP, closed by Close", true, true, nil, knx.ErrClosed, false},
		{"UDP, lost", false, true, fmt.Errorf("%w: heartbeat", knx.ErrConnectionLost), knx.ErrConnectionLost, false},
		{"UDP, lost without the sentinel", false, true, errors.New("socket gone"), knx.ErrConnectionLost, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cn := connectedConn(c.stream)
			cn.o.waitConfirm = false
			if c.closed {
				cn.err = c.cause
				close(cn.closing)
			}
			err := cn.Send(context.Background(), frame)
			if !errors.Is(err, c.want) || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("Send = %v; want it to match %v and wrap net.ErrClosed", err, c.want)
			}
			if c.want == knx.ErrConnectionLost && errors.Is(err, knx.ErrClosed) {
				t.Errorf("Send = %v matches knx.ErrClosed too", err)
			}
			select {
			case ev := <-cn.lost:
				if !c.wantLost {
					t.Errorf("loss signalled after shutdown: %v", ev.err)
				}
			default:
				if c.wantLost {
					t.Error("loss not signalled")
				}
			}
		})
	}
}
