// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// Lifecycle contract tests (TESTING.md, "Lifecycle contract matrix"). Every
// wait is on an event: a frame a client received, a metrics callback, a
// value on a channel. The constant wait only bounds a wait that would
// otherwise hang.

// errorLog keeps the entries logged at error level.
type errorLog struct {
	knx.Logger
	mu      sync.Mutex
	entries []string
	logged  chan struct{}
}

func newErrorLog() *errorLog {
	return &errorLog{Logger: knx.NopLogger(), logged: make(chan struct{}, 16)}
}

func (e *errorLog) Errorf(format string, a ...any) {
	parts := make([]string, len(a))
	for i, v := range a {
		switch x := v.(type) {
		case error:
			parts[i] = x.Error()
		case []byte:
			parts[i] = string(x)
		default:
			parts[i] = fmt.Sprint(v)
		}
	}
	e.mu.Lock()
	e.entries = append(e.entries, strings.Join(parts, "\n"))
	e.mu.Unlock()
	e.logged <- struct{}{}
}

func (e *errorLog) all() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.entries...)
}

// L14: a Start that fails leaves no socket open and no goroutine running,
// whichever step refused.
func TestStartFailureReleasesSockets(t *testing.T) {
	leak.Check(t)
	// The first sockets of the process initialise the poller.
	warm, _ := start(t)
	_ = warm
	for name, opts := range map[string][]server.Option{
		"listen address":           {server.WithListenAddr("127.0.0.1:x")},
		"group":                    {server.WithListenAddr("127.0.0.1:0"), server.WithMulticastGroup("239.1.1.1:x")},
		"unicast group":            {server.WithListenAddr("127.0.0.1:0"), server.WithMulticastGroup("10.0.0.1:3671")},
		"interface":                {server.WithListenAddr("127.0.0.1:0"), server.WithInterface("no-such-interface0")},
		"routing port":             {server.WithListenAddr("127.0.0.1:0"), server.WithRouting(true), server.WithDiscovery(false)},
		"routing port without TCP": {server.WithListenAddr("127.0.0.1:0"), server.WithRouting(true), server.WithDiscovery(false), server.WithTCP(false)},
		"routing on a fixed port":  {server.WithListenAddr(fmt.Sprintf("127.0.0.1:%d", fakeknx.FreePort(t))), server.WithRouting(true), server.WithDiscovery(false)},
		"address of another host":  {server.WithListenAddr("192.0.2.1:0"), server.WithDiscovery(false)},
	} {
		t.Run(name, func(t *testing.T) {
			for range 3 {
				s, err := server.New(opts...)
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				before := openFDs()
				err = s.Start(context.Background())
				after := openFDs()
				if err == nil {
					s.Close()
					t.Fatal("Start succeeded")
				}
				if before >= 0 && after != before {
					t.Fatalf("%d descriptors open after the failed Start, %d before", after, before)
				}
				if s.Addr().IsValid() {
					t.Errorf("Addr() = %s after the failed Start", s.Addr())
				}
				if err := s.Close(); err != nil {
					t.Errorf("Close after the failed Start = %v", err)
				}
			}
		})
	}
}

// L2: Close from several goroutines, with clients connected over UDP and
// TCP: every Close returns, the clients are disconnected and the sockets
// are released once.
func TestCloseConcurrently(t *testing.T) {
	leak.Check(t)
	warm, _ := start(t)
	_ = warm
	before := openFDs()
	m := newMetrics()
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false), server.WithTunnelAddresses(slot1, slot2), server.WithMetrics(m))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	udp, err := tunnel.Dial(ctx(t), addrOf(s).String())
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := tunnel.Dial(ctx(t), addrOf(s).String(), tunnel.WithTCP())
	if err != nil {
		t.Fatal(err)
	}
	const closers = 8
	begin := make(chan struct{})
	errs := make(chan error, closers)
	for range closers {
		go func() {
			<-begin
			errs <- s.Close()
		}()
	}
	close(begin)
	for range closers {
		if err := recv(t, errs, "a Close to return"); err != nil {
			t.Errorf("Close = %v", err)
		}
	}
	// The server ended both connections: the clients see them lost.
	for name, c := range map[string]*tunnel.Conn{"UDP": udp, "TCP": tcp} {
		recv(t, c.Done(), "the "+name+" client to see the connection end")
		if err := c.Err(); !errors.Is(err, knx.ErrConnectionLost) {
			t.Errorf("%s client: Err() = %v, want knx.ErrConnectionLost", name, err)
		}
		c.Close()
	}
	if n := len(s.Connections()); n != 0 {
		t.Errorf("%d connections after Close", n)
	}
	if n := m.get(func(m *metrics) int { return len(m.disconnects) }); n != 2 {
		t.Errorf("%d disconnections reported, want 2", n)
	}
	if after := openFDs(); before >= 0 && after != before {
		t.Errorf("%d descriptors open after Close, %d before Start", after, before)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close again = %v", err)
	}
}

// secureRouter returns a server with secure routing on a fresh group, not
// started, and the endpoint to inject frames at.
func secureRouter(t *testing.T, key secure.Key, latency time.Duration) (*server.Server, *metrics, netip.AddrPort) {
	t.Helper()
	g := fakeknx.Group(t)
	m := newMetrics()
	opts := []server.Option{server.WithListenAddr(fmt.Sprintf(":%d", g.Port())), server.WithMulticastGroup(g.String()),
		server.WithRouting(true), server.WithDiscovery(false), server.WithSecureRouting(key, latency),
		server.WithTunnelAddresses(slot1, slot2), server.WithMetrics(m)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		opts = append(opts, server.WithInterface(lo))
	}
	s, err := server.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, m, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), g.Port())
}

// The timer synchronisation of secure routing runs for its whole window,
// whatever becomes of the context Start was called with: frames are
// accepted only after the window, and with the timer the backbone gave
// during it.
func TestSecureRoutingSynchronisationOutlivesStart(t *testing.T) {
	leak.Check(t)
	key := secure.Key{1, 2, 3}
	s, m, local := secureRouter(t, key, 300*time.Millisecond) // a window of about a second
	startCtx, cancel := context.WithCancel(context.Background())
	if err := s.Start(startCtx); err != nil {
		cancel()
		t.Skipf("cannot join the group: %v", err)
	}
	cancel() // the start-up context ends when Start has returned
	c := dialTunnel(t, s)
	p := fakeknx.Listen(t)
	wrapper := func(timer uint64, v byte) *knxnetip.SecureWrapper {
		plain, _ := knxnetip.Marshal(&knxnetip.RoutingIndication{CEMI: indication(v, 6)})
		w, err := secure.Seal(key, 0, timer, [6]byte{0, 0xfa, 9}, uint16(v), plain)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	// Inside the window nothing is accepted.
	p.Send(local, wrapper(5000, 1))
	m.waitDrop(t, "timer_unsynchronised")
	// A time keeper of the backbone gives its timer.
	const backbone = 1 << 40
	p.Send(local, secure.NewTimerNotify(key, backbone, [6]byte{0, 0xfa, 7}, 1))
	recv(t, s.TimerSynchronized(), "the end of the synchronisation window")
	// A frame older than the backbone's timer is refused, a newer one
	// delivered: the first frame the client gets is the third.
	p.Send(local, wrapper(backbone-10_000, 2))
	m.waitDrop(t, "timer")
	p.Send(local, wrapper(backbone+1000, 3))
	if f := receive(t, c); lastOctet(f) != 3 {
		t.Fatalf("the client received the telegram %d first, want 3", lastOctet(f))
	}
}

// Start and Close of a server with secure routing from two goroutines:
// either Start fails with knx.ErrClosed or Close stops what Start
// started, the routing timer included (run with -race). Close comes at
// once in half of the rounds, and in the others as soon as Start has
// published its socket, which is when it publishes the timer.
func TestStartCloseRaceSecureRouting(t *testing.T) {
	leak.Check(t)
	for round := range 40 {
		s, _, _ := secureRouter(t, secure.Key{1}, 100*time.Millisecond)
		started := make(chan error, 1)
		go func() { started <- s.Start(context.Background()) }()
		var startErr error
		returned := false
		if round%2 == 1 {
			for !s.Addr().IsValid() && !returned {
				select {
				case startErr = <-started:
					returned = true
				default:
					runtime.Gosched()
				}
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if !returned {
			startErr = recv(t, started, "Start to return")
		}
		if startErr != nil && !errors.Is(startErr, knx.ErrClosed) {
			t.Skipf("cannot join the group: %v", startErr)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// L9: a tap may call the server's methods.
func TestTapCallsServer(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	a, b := dialRaw(t, s), dialRaw(t, s)
	seen := make(chan int, 4)
	own := make(chan func(), 1) // the tap's own subscription
	own <- s.Subscribe(func(tg server.Telegram) {
		if tg.Origin != server.FromTunnel {
			return
		}
		n := len(s.Connections())
		if !s.Addr().IsValid() {
			t.Error("Addr() in a tap")
		}
		// Subscribing and unsubscribing, its own subscription included.
		s.Subscribe(func(server.Telegram) {})()
		(<-own)()
		seen <- n
	})
	a.request(0, write(ga, 1))
	if n := recv(t, seen, "the tap"); n != 2 {
		t.Errorf("Connections() in a tap returned %d connections, want 2", n)
	}
	if f := b.nextFrame(); lastOctet(f) != 1 {
		t.Fatalf("the other client got %v", f)
	}
	// The tap removed itself: the next telegram is distributed without it.
	a.request(1, write(ga, 2))
	if f := b.nextFrame(); lastOctet(f) != 2 {
		t.Fatalf("the other client got %v", f)
	}
	select {
	case n := <-seen:
		t.Errorf("the tap ran again after it removed itself (%d)", n)
	default:
	}
}

// L10: a tap ends the server by calling Close from another goroutine;
// Close completes once the tap has returned.
func TestTapClosesServer(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	a := dialRaw(t, s)
	closed := make(chan error, 1)
	disconnect := make(chan struct{})
	a.p.Handle(func(_ *fakeknx.Peer, d fakeknx.Datagram) bool {
		if _, ok := d.Msg.(*knxnetip.DisconnectRequest); ok {
			close(disconnect)
			return true
		}
		return false
	})
	inTap := make(chan struct{})
	s.Subscribe(func(server.Telegram) {
		go func() { closed <- s.Close() }()
		// Close has begun when it disconnects the client. It waits for
		// the reader, which runs this tap.
		<-disconnect
		select {
		case err := <-closed:
			t.Errorf("Close returned %v while the tap was running", err)
		default:
		}
		close(inTap)
	})
	a.request(0, write(ga, 1))
	recv(t, inTap, "the tap")
	if err := recv(t, closed, "Close to return after the tap"); err != nil {
		t.Fatalf("Close = %v", err)
	}
}

// A tap that does not return normally is stopped there and logged with
// its stack; the telegram is distributed and the server goes on.
func TestTapDoesNotReturnNormally(t *testing.T) {
	leak.Check(t)
	log := newErrorLog()
	s, _ := start(t, server.WithLogger(log))
	a, b := dialRaw(t, s), dialRaw(t, s)
	var seen sync.Map
	s.Subscribe(func(tg server.Telegram) {
		if tg.Origin == server.FromTunnel && lastOctet(tg.Frame) == 1 {
			var none []int
			_ = none[tg.Channel] // index out of range
		}
	})
	s.Subscribe(func(tg server.Telegram) { seen.Store(lastOctet(tg.Frame), true) })
	for i, v := range []byte{1, 2} {
		a.request(uint8(i), write(ga, v))
		if f := b.nextFrame(); lastOctet(f) != v {
			t.Fatalf("the other client got %v, want the telegram %d", f, v)
		}
		if con := a.nextFrame(); lastOctet(con) != v {
			t.Fatalf("confirmation %v", con)
		}
	}
	recv(t, log.logged, "the entry for the tap")
	entries := log.all()
	if len(entries) != 1 {
		t.Fatalf("%d entries at error level, want 1: %q", len(entries), entries)
	}
	for _, part := range []string{"server.Subscribe did not return normally", "index out of range", "TestTapDoesNotReturnNormally"} {
		if !strings.Contains(entries[0], part) {
			t.Errorf("the entry does not hold %q:\n%s", part, entries[0])
		}
	}
	for _, v := range []byte{1, 2} {
		if _, ok := seen.Load(v); !ok {
			t.Errorf("the other tap did not see the telegram %d", v)
		}
	}
}

// A change handler of a virtual device that does not return normally is
// stopped there and logged with its stack; the other devices, the clients
// and the server go on.
func TestDeviceHandlerDoesNotReturnNormally(t *testing.T) {
	leak.Check(t)
	log := newErrorLog()
	s, _ := start(t, server.WithLogger(log))
	faulty := device.New("faulty", knx.MustParseIndividualAddress("1.1.1"))
	sw, _ := device.NewGroupObject("switch", "1.001", "CRW", "1/2/3")
	faulty.Add(sw)
	faulty.OnChange(func(e device.Event) {
		var none []int
		_ = none[len(e.Raw)] // index out of range
	})
	sound := device.New("sound", knx.MustParseIndividualAddress("1.1.2"))
	lamp, _ := device.NewGroupObject("lamp", "1.001", "CRW", "1/2/3")
	sound.Add(lamp)
	changed := make(chan device.Event, 4)
	sound.OnChange(func(e device.Event) { changed <- e })
	s.AddDevice(faulty)
	s.AddDevice(sound)

	a, b := dialRaw(t, s), dialRaw(t, s)
	tpdu, _ := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{1}, Small: true})
	for i := range 2 {
		f := write(ga, 0)
		f.TPDU = tpdu
		a.request(uint8(i), f)
		if e := recv(t, changed, "the other device's handler"); e.Value != true {
			t.Fatalf("event %+v", e)
		}
		b.nextFrame()
		a.nextFrame()
		recv(t, log.logged, "the entry for the handler")
	}
	entries := log.all()
	if len(entries) != 2 {
		t.Fatalf("%d entries at error level, want 2: %q", len(entries), entries)
	}
	for _, part := range []string{"device.Device.Handle did not return normally", "index out of range", "TestDeviceHandlerDoesNotReturnNormally"} {
		if !strings.Contains(entries[0], part) {
			t.Errorf("the entry does not hold %q:\n%s", part, entries[0])
		}
	}
	// The object was set before its handler ran.
	if v, ok := sw.Raw(); !ok || len(v) != 1 || v[0] != 1 {
		t.Errorf("object of the device whose handler did not return: % X %v", v, ok)
	}
}

// A server takes four device management connections; the fifth is refused
// with E_NO_MORE_CONNECTIONS and takes the place of none, and one is free
// again when a client disconnects.
func TestDeviceManagementLimit(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	cri := knxnetip.CRI{Type: knxnetip.DeviceManagementConnection}
	var clients []*raw
	for i := range 4 {
		r := newRaw(t, s)
		if resp := r.connect(cri); resp.Status != knxnetip.StatusNoError {
			t.Fatalf("device management connection %d: %s", i+1, resp.Status)
		}
		clients = append(clients, r)
	}
	fifth := newRaw(t, s)
	if resp := fifth.connect(cri); resp.Status != knxnetip.StatusNoMoreConnections {
		t.Fatalf("fifth device management connection: %s, want E_NO_MORE_CONNECTIONS", resp.Status)
	}
	if n := len(s.Connections()); n != 4 {
		t.Fatalf("%d connections, want 4", n)
	}
	// Tunnelling connections have their own limit.
	if resp := newRaw(t, s).connect(knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)); resp.Status != knxnetip.StatusNoError {
		t.Fatalf("tunnelling connection next to four device management connections: %s", resp.Status)
	}
	first := clients[0]
	first.p.Send(first.srv, &knxnetip.DisconnectRequest{Channel: first.ch, Control: first.p.HPAI()})
	if resp, _ := fakeknx.Expect[*knxnetip.DisconnectResponse](first.p, wait); resp.Status != knxnetip.StatusNoError {
		t.Fatalf("disconnect: %s", resp.Status)
	}
	if resp := fifth.connect(cri); resp.Status != knxnetip.StatusNoError {
		t.Fatalf("device management connection after one ended: %s", resp.Status)
	}
}
