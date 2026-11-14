// SPDX-License-Identifier: MIT

package tunnel_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/tunnel"
)

// stalledServer accepts one TCP tunnel, answers its CONNECT_REQUEST and
// then never reads again. The server's socket closes at the end of the
// test.
func stalledServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conns := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(4096)
		}
		conns <- c
		if _, err := knxnetip.ReadFrame(c); err != nil {
			return
		}
		b, _ := knxnetip.Marshal(&knxnetip.ConnectResponse{Channel: 1, Data: knxnetip.TCPHPAI(),
			CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
		_, _ = c.Write(b)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case c := <-conns:
			_ = c.Close()
		default:
		}
	})
	return ln.Addr().String()
}

// fillUntilError sends large group writes until one fails, each Send
// bounded by perSend (none when zero). It returns the error and how long
// the failing Send took.
func fillUntilError(t *testing.T, c *tunnel.Conn, perSend time.Duration) (time.Duration, error) {
	t.Helper()
	tpdu := make([]byte, 200)
	tpdu[1] = 0x80
	f := cemi.NewGroupFrame(cemi.LDataReq, 0, group, knx.PriorityLow, tpdu)
	end := time.Now().Add(60 * time.Second)
	for time.Now().Before(end) {
		ctx, cancel := context.Background(), context.CancelFunc(func() {})
		if perSend > 0 {
			ctx, cancel = context.WithTimeout(ctx, perSend)
		}
		start := time.Now()
		err := c.Send(ctx, f)
		cancel()
		if err != nil {
			return time.Since(start), err
		}
	}
	t.Fatal("Send never failed against a server that does not read")
	return 0, nil
}

func TestTCPServerStopsReading(t *testing.T) {
	t.Run("Send honours its ctx", func(t *testing.T) {
		leak.Check(t)
		c, err := tunnel.Dial(context.Background(), stalledServer(t), tunnel.WithTCP(),
			tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(30*time.Second),
			tunnel.WithConnectTimeout(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		took, err := fillUntilError(t, c, 300*time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, knx.ErrConnectionLost) {
			t.Errorf("Send: %v", err)
		}
		if took > 2*time.Second {
			t.Errorf("Send returned %v after it started, ctx was 300ms", took)
		}
		start := time.Now()
		closed := make(chan struct{})
		go func() { _ = c.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Close does not return")
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("Close took %v", d)
		}
	})
	t.Run("write timeout loses the connection", func(t *testing.T) {
		leak.Check(t)
		c, err := tunnel.Dial(context.Background(), stalledServer(t), tunnel.WithTCP(),
			tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(200*time.Millisecond),
			tunnel.WithConnectTimeout(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		took, err := fillUntilError(t, c, 0)
		if !errors.Is(err, knx.ErrConnectionLost) {
			t.Errorf("Send: %v, want ErrConnectionLost", err)
		}
		if took > 2*time.Second {
			t.Errorf("Send returned after %v, request timeout 200ms", took)
		}
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the lost connection does not close the Conn")
		}
		if !errors.Is(c.Err(), knx.ErrConnectionLost) {
			t.Errorf("Err: %v", c.Err())
		}
		_ = c.Close()
	})
}
