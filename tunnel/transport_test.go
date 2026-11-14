// SPDX-License-Identifier: MIT

package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx/secure"
)

// pipeTransport returns a TCP transport on one end of a synchronous pipe:
// a write blocks until the other end reads it.
func pipeTransport(t *testing.T, timeout time.Duration) (*tcpTransport, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return &tcpTransport{c: a, writeTimeout: timeout}, b
}

func TestTCPWriteBounded(t *testing.T) {
	frame := []byte{6, 0x10, 2, 9, 0, 6}
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		ctx     func() (context.Context, context.CancelFunc)
		read    int // octets the peer reads before it stops
		want    error
		sticky  bool // the transport refuses later writes
	}{
		{"ctx ended before the write", time.Minute, func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, 0, context.Canceled, false},
		{"ctx deadline, nothing written", time.Minute, func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		}, 0, context.DeadlineExceeded, false},
		{"ctx cancelled, nothing written", time.Minute, func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(50*time.Millisecond, cancel)
			return ctx, cancel
		}, 0, context.Canceled, false},
		{"write timeout", 50 * time.Millisecond, func() (context.Context, context.CancelFunc) {
			return context.Background(), func() {}
		}, 0, errWriteTimeout, true},
		{"default write timeout", 0, func() (context.Context, context.CancelFunc) {
			return context.Background(), func() {}
		}, 0, errWriteTimeout, true},
		{"ctx deadline after part of the frame", time.Minute, func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		}, 2, errWriteTimeout, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, peer := pipeTransport(t, tc.timeout)
			if tc.read > 0 {
				go func() { _, _ = io.ReadFull(peer, make([]byte, tc.read)) }()
			}
			ctx, cancel := tc.ctx()
			defer cancel()
			start := time.Now()
			err := tr.writeContext(ctx, frame, netip.AddrPort{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("write: %v, want %v", err, tc.want)
			}
			if d := time.Since(start); d > defaultWriteTimeout+time.Second {
				t.Errorf("write returned after %v", d)
			}
			// A later write: refused at once on a broken stream, otherwise
			// it goes through.
			go func() { _, _ = io.Copy(io.Discard, peer) }()
			err = tr.writeTo(frame, netip.AddrPort{})
			if tc.sticky != (err != nil) {
				t.Errorf("later write: %v, sticky %v", err, tc.sticky)
			}
		})
	}
}

func TestTCPWriteOK(t *testing.T) {
	tr, peer := pipeTransport(t, time.Second)
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 6)
		_, _ = io.ReadFull(peer, b)
		got <- b
	}()
	ctx, cancel := context.WithCancel(context.Background())
	if err := tr.writeContext(ctx, []byte{6, 0x10, 2, 9, 0, 6}, netip.AddrPort{}); err != nil {
		t.Fatal(err)
	}
	<-got
	// Cancelling after the write must not cut the next one.
	cancel()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	if err := tr.writeTo([]byte{6, 0x10, 2, 9, 0, 6}, netip.AddrPort{}); err != nil {
		t.Fatal(err)
	}
}

func TestUDPWriteContext(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tr := udpTransport{c: c}
	to := netip.MustParseAddrPort(c.LocalAddr().String())
	ctx, cancel := context.WithCancel(context.Background())
	if err := tr.writeContext(ctx, []byte{1}, to); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := tr.writeContext(ctx, []byte{1}, to); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// Closing a secure session whose server does not read returns within
// the close write timeout.
func TestSecureCloseServerNotReading(t *testing.T) {
	tr, _ := pipeTransport(t, time.Minute)
	st := &secureTransport{inner: tr, sess: secure.NewSession(1, secure.Key{1}, [6]byte{2})}
	start := time.Now()
	if err := st.close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > closeWriteTimeout+time.Second {
		t.Errorf("close took %v", d)
	}
	if err := st.writeTo([]byte{6, 0x10, 2, 9, 0, 6}, netip.AddrPort{}); err == nil {
		t.Error("write after close")
	}
}
