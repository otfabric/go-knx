// SPDX-License-Identifier: MIT

package tunnel

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/otfabric/go-knx/knxnetip"
)

// transport carries KNXnet/IP frames: UDP datagrams or a TCP stream.
type transport interface {
	writeTo(b []byte, to netip.AddrPort) error
	// readFrom returns the next frame and its source; for TCP the source
	// is always the server.
	readFrom(buf []byte) (int, netip.AddrPort, error)
	close() error
	localAddr() net.Addr
	// stream reports a TCP transport: no TUNNELLING_ACKs, one peer.
	stream() bool
}

type udpTransport struct{ c *net.UDPConn }

func (t udpTransport) writeTo(b []byte, to netip.AddrPort) error {
	_, err := t.c.WriteToUDPAddrPort(b, to)
	return err
}

func (t udpTransport) readFrom(buf []byte) (int, netip.AddrPort, error) {
	n, from, err := t.c.ReadFromUDPAddrPort(buf)
	return n, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), err
}

func (t udpTransport) close() error        { return t.c.Close() }
func (t udpTransport) localAddr() net.Addr { return t.c.LocalAddr() }
func (udpTransport) stream() bool          { return false }

type tcpTransport struct {
	c      net.Conn
	server netip.AddrPort
	wmu    sync.Mutex
}

func (t *tcpTransport) writeTo(b []byte, _ netip.AddrPort) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err := t.c.Write(b)
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

func (t *tcpTransport) close() error        { return t.c.Close() }
func (t *tcpTransport) localAddr() net.Addr { return t.c.LocalAddr() }
func (*tcpTransport) stream() bool          { return true }

// errStreamClosed reports a TCP connection the server closed.
var errStreamClosed = errors.New("tunnel: the server closed the TCP connection")
