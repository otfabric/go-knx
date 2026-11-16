// SPDX-License-Identifier: MIT

package tunnel_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// faultyConn is a connection whose writes fail once the test says so.
type faultyConn struct {
	net.Conn
	fail atomic.Bool
}

var errInjected = errors.New("injected write failure")

func (c *faultyConn) Write(b []byte) (int, error) {
	if c.fail.Load() {
		return 0, errInjected
	}
	return c.Conn.Write(b)
}

// tcpServer starts a go-knx server with TCP on loopback and returns its
// address.
func tcpServer(t *testing.T) string {
	t.Helper()
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s.Addr().String()
}

// WithDialer opens the TCP connection of a tunnel: the dialer gets the
// network, the server's address and a context bounded by the connect
// timeout, the tunnel runs over the connection it returns, and a fault of
// that connection is a fault of the tunnel.
func TestWithDialer(t *testing.T) {
	leak.Check(t)
	addr := tcpServer(t)
	var mu sync.Mutex
	var network, address string
	var deadline time.Duration
	var conn *faultyConn
	dial := func(ctx context.Context, n, a string) (net.Conn, error) {
		d, _ := ctx.Deadline()
		var nd net.Dialer
		c, err := nd.DialContext(ctx, n, a)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		network, address, deadline = n, a, time.Until(d)
		conn = &faultyConn{Conn: c}
		return conn, nil
	}
	c, err := tunnel.Dial(ctx(t), addr, tunnel.WithTCP(), tunnel.WithDialer(dial), tunnel.WithConnectTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	mu.Lock()
	if network != "tcp4" || address != addr || deadline <= 0 || deadline > 3*time.Second {
		t.Errorf("dialer called with %q %q and a deadline in %v, want tcp4 %s and one within the connect timeout of 3s", network, address, deadline, addr)
	}
	fc := conn
	mu.Unlock()
	if !c.TCP() {
		t.Fatal("the tunnel is not over TCP")
	}
	if err := c.Send(ctx(t), groupWrite(1)); err != nil {
		t.Fatalf("Send over the dialer's connection = %v", err)
	}
	fc.fail.Store(true)
	if err := c.Send(ctx(t), groupWrite(2)); !errors.Is(err, knx.ErrConnectionLost) || !errors.Is(err, errInjected) {
		t.Fatalf("Send over a connection whose writes fail = %v, want knx.ErrConnectionLost wrapping the write error", err)
	}
}

// A dialer that fails, or returns no connection, fails Dial and leaves
// nothing open; WithDialer needs TCP and excludes WithLocalAddr; nil keeps
// the default.
func TestWithDialerErrors(t *testing.T) {
	leak.Check(t)
	addr := tcpServer(t)
	errDial := errors.New("refused by the allowlist")
	pipeClosed := make(chan struct{})
	for name, tc := range map[string]struct {
		opts []tunnel.Option
		want error
	}{
		"dialer error": {[]tunnel.Option{tunnel.WithTCP(), tunnel.WithDialer(func(context.Context, string, string) (net.Conn, error) {
			return nil, errDial
		})}, errDial},
		"no connection": {[]tunnel.Option{tunnel.WithTCP(), tunnel.WithDialer(func(context.Context, string, string) (net.Conn, error) {
			return nil, nil
		})}, knx.ErrInvalidOption},
		"a connection and an error": {[]tunnel.Option{tunnel.WithTCP(), tunnel.WithDialer(func(context.Context, string, string) (net.Conn, error) {
			c, peer := net.Pipe()
			go func() {
				// The connection is closed: the peer's read ends.
				_, _ = peer.Read(make([]byte, 1))
				close(pipeClosed)
			}()
			return c, errDial
		})}, errDial},
		"UDP": {[]tunnel.Option{tunnel.WithDialer(func(context.Context, string, string) (net.Conn, error) {
			t.Error("dialer called for a UDP tunnel")
			return nil, errDial
		})}, knx.ErrInvalidOption},
		"local address": {[]tunnel.Option{tunnel.WithTCP(), tunnel.WithLocalAddr("127.0.0.1:0"), tunnel.WithDialer(func(context.Context, string, string) (net.Conn, error) {
			t.Error("dialer called with WithLocalAddr")
			return nil, errDial
		})}, knx.ErrInvalidOption},
	} {
		t.Run(name, func(t *testing.T) {
			before := openFDs()
			c, err := tunnel.Dial(ctx(t), addr, tc.opts...)
			if c != nil {
				c.Close()
				t.Fatal("Dial returned a Conn")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Dial = %v, want an error matching %v", err, tc.want)
			}
			if after := openFDs(); before >= 0 && after != before {
				t.Errorf("%d descriptors open after the failed Dial, %d before", after, before)
			}
		})
	}
	recv(t, pipeClosed, "Dial to close the connection the dialer returned with its error")
	c, err := tunnel.Dial(ctx(t), addr, tunnel.WithTCP(), tunnel.WithDialer(nil))
	if err != nil {
		t.Fatalf("Dial with WithDialer(nil) = %v", err)
	}
	c.Close()
}
