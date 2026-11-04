// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// chaos is what the proxy does to each datagram, in per cent.
type chaos struct {
	drop, dup, reorder int
	// delay is the largest delay of a datagram; reordered ones wait up
	// to three times as long, so that later ones overtake them.
	delay time.Duration
}

// chaosProxy relays the datagrams of one client to a server and back,
// dropping, duplicating, delaying and reordering them with a seeded
// generator. The client must use route back HPAIs (tunnel.WithNAT), so
// that the server answers to the proxy.
type chaosProxy struct {
	down, up *net.UDPConn
	server   netip.AddrPort

	mu     sync.Mutex
	rng    *rand.Rand
	c      chaos
	client netip.AddrPort

	blackhole atomic.Bool
	wg        sync.WaitGroup
	closed    chan struct{}
	stats     struct{ relayed, dropped, duplicated, reordered atomic.Int64 }
}

func newChaosProxy(t *testing.T, server string, seed uint64, c chaos) *chaosProxy {
	t.Helper()
	lo := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	down, err := net.ListenUDP("udp4", lo)
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.ListenUDP("udp4", lo)
	if err != nil {
		t.Fatal(err)
	}
	p := &chaosProxy{down: down, up: up, server: netip.MustParseAddrPort(server), c: c,
		rng: rand.New(rand.NewPCG(seed, ^seed)), closed: make(chan struct{})}
	p.wg.Add(2)
	go p.relay(down, true)
	go p.relay(up, false)
	t.Cleanup(p.Close)
	return p
}

func (p *chaosProxy) Addr() string { return localAddr(p.down).String() }

// set replaces the chaos (zero: a faithful relay).
func (p *chaosProxy) set(c chaos) { p.mu.Lock(); p.c = c; p.mu.Unlock() }

// Close stops the relays and waits for the delayed datagrams.
func (p *chaosProxy) Close() {
	select {
	case <-p.closed:
		return
	default:
	}
	close(p.closed)
	_ = p.down.Close()
	_ = p.up.Close()
	p.wg.Wait()
}

func (p *chaosProxy) relay(from *net.UDPConn, toServer bool) {
	defer p.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, src, err := from.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		b := append([]byte(nil), buf[:n]...)
		out, to := p.up, p.server
		p.mu.Lock()
		if toServer {
			p.client = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		} else {
			out, to = p.down, p.client
		}
		c := p.c
		// Every decision comes from the seeded generator, in the order
		// the datagrams arrive.
		roll := func(pct int) bool { return pct > 0 && p.rng.IntN(100) < pct }
		drop, dup, reorder := roll(c.drop), roll(c.dup), roll(c.reorder)
		var delays [2]time.Duration
		for i := range delays {
			if c.delay > 0 {
				delays[i] = time.Duration(p.rng.Int64N(int64(c.delay)))
			}
			if reorder {
				delays[i] += c.delay + time.Duration(p.rng.Int64N(int64(2*c.delay+1)))
			}
		}
		p.mu.Unlock()
		if drop || p.blackhole.Load() || !to.IsValid() {
			p.stats.dropped.Add(1)
			continue
		}
		copies := 1
		if dup {
			copies = 2
			p.stats.duplicated.Add(1)
		}
		if reorder {
			p.stats.reordered.Add(1)
		}
		for i := 0; i < copies; i++ {
			p.stats.relayed.Add(1)
			if delays[i] == 0 {
				_, _ = out.WriteToUDPAddrPort(b, to)
				continue
			}
			p.wg.Add(1)
			time.AfterFunc(delays[i], func() {
				defer p.wg.Done()
				select {
				case <-p.closed:
				default:
					_, _ = out.WriteToUDPAddrPort(b, to)
				}
			})
		}
	}
}

func (p *chaosProxy) String() string {
	return fmt.Sprintf("relayed %d, dropped %d, duplicated %d, reordered %d",
		p.stats.relayed.Load(), p.stats.dropped.Load(), p.stats.duplicated.Load(), p.stats.reordered.Load())
}

// countDeliveries counts the group writes the server receives from
// tunnels, by their value (the last TPDU octet).
func countDeliveries(t *testing.T, s *server.Server) func(v byte) int {
	var mu sync.Mutex
	got := map[byte]int{}
	cancel := s.Subscribe(func(tg server.Telegram) {
		if tg.Origin != server.FromTunnel || len(tg.Frame.TPDU) < 3 {
			return
		}
		mu.Lock()
		got[tg.Frame.TPDU[len(tg.Frame.TPDU)-1]]++
		mu.Unlock()
	})
	t.Cleanup(cancel)
	return func(v byte) int { mu.Lock(); defer mu.Unlock(); return got[v] }
}

func waitConnected(t *testing.T, c *tunnel.Conn, d time.Duration) {
	t.Helper()
	eventually(t, d, "the tunnel to reconnect", func() bool { return c.State() == knx.StateConnected })
}

// TestChaosExactlyOnce: group writes through a proxy that drops,
// duplicates, delays and reorders datagrams in both directions. A write
// that returns nil reached the server exactly once; one that fails reached
// it at most once; no write is delivered twice. Lost connections come back
// (WithReconnect), and with the chaos switched off every write succeeds.
func TestChaosExactlyOnce(t *testing.T) {
	for _, seed := range []uint64{1, 2} {
		t.Run(fmt.Sprint("seed ", seed), func(t *testing.T) {
			leak.Check(t)
			s, addr := startServer(t, server.WithRequestTimeout(100*time.Millisecond))
			delivered := countDeliveries(t, s)
			p := newChaosProxy(t, addr, seed, chaos{drop: 10, dup: 10, reorder: 10, delay: 15 * time.Millisecond})
			c := ctx(t)
			var cl *client.Client
			var err error
			for range 5 { // the CONNECT_REQUEST may be dropped
				dc, cancel := context.WithTimeout(c, time.Second)
				cl, err = client.DialTunnel(dc, p.Addr(), []tunnel.Option{
					tunnel.WithNAT(true),
					tunnel.WithConnectTimeout(200 * time.Millisecond),
					tunnel.WithRequestTimeout(100 * time.Millisecond),
					tunnel.WithConfirm(true, 300*time.Millisecond),
					tunnel.WithReconnect(20*time.Millisecond, 100*time.Millisecond),
				})
				cancel()
				if err == nil {
					break
				}
			}
			if err != nil {
				t.Fatalf("dial through the proxy: %v", err)
			}
			defer cl.Close()
			conn := cl.Link().(*tunnel.Conn)
			g := knx.MustParseGroupAddress("1/2/3")
			const writes = 25
			results := make([]error, writes+1)
			for v := 1; v <= writes; v++ {
				if conn.State() != knx.StateConnected {
					waitConnected(t, conn, 3*time.Second)
				}
				wc, cancel := context.WithTimeout(c, 2*time.Second)
				results[v] = cl.GroupWrite(wc, g, uint8(v), withDPT5)
				cancel()
			}
			p.set(chaos{})
			// A DISCONNECT_REQUEST the proxy dropped leaves the client on a
			// channel the server has closed: the first write afterwards may
			// fail and reconnect. Then the path is clean.
			settled := false
			for range 3 {
				waitConnected(t, conn, 3*time.Second)
				wc, cancel := context.WithTimeout(c, 2*time.Second)
				err := cl.GroupWrite(wc, g, uint8(200), withDPT5)
				cancel()
				if err == nil {
					settled = true
					break
				}
			}
			if !settled {
				t.Fatal("no write succeeds after the chaos stopped")
			}
			for v := writes + 1; v <= writes+3; v++ {
				if err := cl.GroupWrite(c, g, uint8(v), withDPT5); err != nil {
					t.Fatalf("write %d without chaos: %v", v, err)
				}
			}
			// Delayed datagrams settle.
			time.Sleep(100 * time.Millisecond)
			ok := 0
			for v := 1; v <= writes; v++ {
				n := delivered(byte(v))
				switch {
				case n > 1:
					t.Errorf("write %d delivered %d times (result %v)", v, n, results[v])
				case results[v] == nil && n != 1:
					t.Errorf("write %d succeeded but was delivered %d times", v, n)
				}
				if results[v] == nil {
					ok++
				}
			}
			for v := writes + 1; v <= writes+3; v++ {
				if n := delivered(byte(v)); n != 1 {
					t.Errorf("write %d without chaos delivered %d times", v, n)
				}
			}
			if ok < writes/2 {
				t.Errorf("only %d of %d writes succeeded", ok, writes)
			}
			t.Logf("%d of %d writes succeeded; proxy %s", ok, writes, p)
		})
	}
}

var withDPT5 = client.WithDPT("5.010")

// TestChaosBlackhole: the path to the server goes dark for longer than
// the heartbeat tolerates. The client notices, reconnects once the path
// is back, and its writes work again; the server drops the dead channel.
func TestChaosBlackhole(t *testing.T) {
	leak.Check(t)
	s, addr := startServer(t, server.WithConnectionAliveTime(time.Second))
	delivered := countDeliveries(t, s)
	p := newChaosProxy(t, addr, 9, chaos{})
	c := ctx(t)
	var mu sync.Mutex
	var states []knx.State
	cl, err := client.DialTunnel(c, p.Addr(), []tunnel.Option{
		tunnel.WithNAT(true),
		tunnel.WithConnectTimeout(200 * time.Millisecond),
		tunnel.WithHeartbeat(100*time.Millisecond, 100*time.Millisecond, 2),
		tunnel.WithConfirm(true, 500*time.Millisecond),
		tunnel.WithReconnect(20*time.Millisecond, 100*time.Millisecond),
		tunnel.WithStateHandler(func(s knx.State, _ error) { mu.Lock(); states = append(states, s); mu.Unlock() }),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	conn := cl.Link().(*tunnel.Conn)
	g := knx.MustParseGroupAddress("1/2/3")
	if err := cl.GroupWrite(c, g, uint8(1), withDPT5); err != nil {
		t.Fatal(err)
	}
	first := conn.Channel()
	p.blackhole.Store(true)
	eventually(t, 3*time.Second, "the client to notice the dead path", func() bool { return conn.State() != knx.StateConnected })
	time.Sleep(200 * time.Millisecond)
	p.blackhole.Store(false)
	waitConnected(t, conn, 3*time.Second)
	if err := cl.GroupWrite(c, g, uint8(2), withDPT5); err != nil {
		t.Fatalf("write after the reconnection: %v (channel %d, before %d, delivered %d)", err, conn.Channel(), first, delivered(2))
	}
	if delivered(1) != 1 || delivered(2) != 1 {
		t.Fatalf("deliveries %d %d", delivered(1), delivered(2))
	}
	// The old channel had no heartbeat since the blackhole: the server
	// drops it after its alive time and keeps the new one.
	eventually(t, 3*time.Second, "the server to drop the dead channel", func() bool {
		cs := s.Connections()
		return len(cs) == 1 && cs[0].Channel == conn.Channel()
	})
	mu.Lock()
	defer mu.Unlock()
	if len(states) < 3 || states[len(states)-1] != knx.StateConnected {
		t.Fatalf("states %v (first channel %d, now %d)", states, first, conn.Channel())
	}
}
