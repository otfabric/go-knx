// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// TestReconnectAfterServerRestart: the server goes away (and says so),
// comes back on the same endpoint, and a client with WithReconnect gets a
// new channel and works again.
func TestReconnectAfterServerRestart(t *testing.T) {
	leak.Check(t)
	s1, addr := startServer(t)
	var mu sync.Mutex
	var states []knx.State
	c, err := client.DialTunnel(ctx(t), addr, []tunnel.Option{
		tunnel.WithReconnect(20*time.Millisecond, 100*time.Millisecond),
		tunnel.WithConnectTimeout(200 * time.Millisecond),
		tunnel.WithStateHandler(func(s knx.State, _ error) { mu.Lock(); states = append(states, s); mu.Unlock() }),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := knx.MustParseGroupAddress("1/1/1")
	if err := c.GroupWrite(ctx(t), g, true); err != nil {
		t.Fatal(err)
	}
	s1.Close()
	state := func() knx.State { return c.Link().(*tunnel.Conn).State() }
	deadline := time.Now().Add(2 * time.Second)
	for state() != knx.StateReconnecting {
		if time.Now().After(deadline) {
			t.Fatalf("state %s after the server closed", state())
		}
		time.Sleep(5 * time.Millisecond)
	}

	s2, err := server.New(server.WithListenAddr(addr), server.WithDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	deadline = time.Now().Add(5 * time.Second)
	for state() != knx.StateConnected {
		if time.Now().After(deadline) {
			t.Fatalf("not reconnected: %s", state())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(s2.Connections()) != 1 {
		t.Fatalf("connections %+v", s2.Connections())
	}
	if err := c.GroupWrite(ctx(t), g, false); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(states) < 4 || states[len(states)-1] != knx.StateConnected || states[len(states)-2] != knx.StateReconnecting {
		t.Fatalf("states %v", states)
	}
}
