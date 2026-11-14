// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-knx/internal/udp"
	"github.com/otfabric/go-knx/knxnetip"
)

// transport carries KNXnet/IP frames: UDP datagrams or a TCP stream.
type transport interface {
	writeTo(b []byte, to netip.AddrPort) error
	// writeContext is writeTo bounded by ctx as well: a write that cannot
	// start before ctx ends returns ctx.Err() and leaves the transport
	// usable.
	writeContext(ctx context.Context, b []byte, to netip.AddrPort) error
	// readFrom returns the next frame and its source; for TCP the source
	// is always the server.
	readFrom(buf []byte) (int, netip.AddrPort, error)
	close() error
	localAddr() net.Addr
	// stream reports a TCP transport: no TUNNELLING_ACKs, one peer.
	stream() bool
	// setDeadline sets the read and write deadline.
	setDeadline(t time.Time) error
}

type udpTransport struct{ c *net.UDPConn }

func (t udpTransport) writeTo(b []byte, to netip.AddrPort) error {
	_, err := t.c.WriteToUDPAddrPort(b, to)
	return err
}

// writeContext of a datagram does not block on the peer: ctx is only
// checked before the write.
func (t udpTransport) writeContext(ctx context.Context, b []byte, to netip.AddrPort) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.writeTo(b, to)
}

func (t udpTransport) readFrom(buf []byte) (int, netip.AddrPort, error) {
	n, from, err := udp.Read(t.c.ReadFromUDPAddrPort, buf)
	return n, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), err
}

func (t udpTransport) close() error                  { return t.c.Close() }
func (t udpTransport) localAddr() net.Addr           { return t.c.LocalAddr() }
func (udpTransport) stream() bool                    { return false }
func (t udpTransport) setDeadline(d time.Time) error { return t.c.SetDeadline(d) }

// defaultWriteTimeout bounds a TCP write when no other bound is set.
const defaultWriteTimeout = time.Second

type tcpTransport struct {
	c      net.Conn
	server netip.AddrPort
	// writeTimeout bounds every write (defaultWriteTimeout when zero): a
	// server that stops reading fills the send buffer and would otherwise
	// block the writer, and with it Close, for as long as it likes.
	writeTimeout time.Duration

	wmu sync.Mutex
	// werr is the error of a failed write: the stream may end in the
	// middle of a frame, so every later write fails with it.
	werr error
}

func (t *tcpTransport) writeTo(b []byte, to netip.AddrPort) error {
	return t.writeContext(context.Background(), b, to)
}

// writeContext writes one frame within the write timeout and before ctx
// ends. A write that fails, times out or is cut short by ctx after it
// started leaves the stream unusable: that and every later write return an
// error (the caller treats it as a lost connection). A write that ctx ends
// before any octet went out returns ctx.Err() and changes nothing.
func (t *tcpTransport) writeContext(ctx context.Context, b []byte, _ netip.AddrPort) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if t.werr != nil {
		return t.werr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := t.writeTimeout
	if timeout <= 0 {
		timeout = defaultWriteTimeout
	}
	deadline := time.Now().Add(timeout)
	d, ctxBound := ctx.Deadline()
	if ctxBound = ctxBound && d.Before(deadline); ctxBound {
		deadline = d
	}
	_ = t.c.SetWriteDeadline(deadline)
	// Cancellation (without a deadline) interrupts the write too. The
	// callback must not outlive the write: it would cut the next one.
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(fired)
		_ = t.c.SetWriteDeadline(time.Now())
	})
	n, err := t.c.Write(b)
	if !stop() {
		<-fired
	}
	if err == nil {
		return nil
	}
	if n == 0 {
		// Nothing went out: the stream is intact.
		if err := ctx.Err(); err != nil {
			return err
		}
		if ctxBound && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		err = fmt.Errorf("%w: the server does not read (%d of %d octets written)", errWriteTimeout, n, len(b))
	}
	t.werr = err
	return err
}

func (t *tcpTransport) readFrom(buf []byte) (int, netip.AddrPort, error) {
	f, err := knxnetip.ReadFrame(t.c)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = errStreamClosed
		}
		return 0, t.server, err
	}
	return copy(buf, f), t.server, nil
}

func (t *tcpTransport) close() error                  { return t.c.Close() }
func (t *tcpTransport) localAddr() net.Addr           { return t.c.LocalAddr() }
func (*tcpTransport) stream() bool                    { return true }
func (t *tcpTransport) setDeadline(d time.Time) error { return t.c.SetDeadline(d) }

// errStreamClosed reports a TCP connection the server closed.
var errStreamClosed = errors.New("tunnel: the server closed the TCP connection")

// errWriteTimeout reports a TCP write the server did not take within the
// write timeout.
var errWriteTimeout = errors.New("tunnel: TCP write timed out")
