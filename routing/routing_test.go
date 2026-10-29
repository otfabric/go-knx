// SPDX-License-Identifier: MIT

package routing_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/routing"
)

const wait = 2 * time.Second

var ga = knx.MustParseGroupAddress("1/2/3")

type metrics struct {
	knx.NopMetrics
	mu      sync.Mutex
	dropped map[string]int
	decode  int
	sent    int
}

func (m *metrics) OnDropped(_ net.Addr, r string) { m.mu.Lock(); m.dropped[r]++; m.mu.Unlock() }
func (m *metrics) OnDecodeError(net.Addr, error)  { m.mu.Lock(); m.decode++; m.mu.Unlock() }
func (m *metrics) OnFrameSent(net.Addr, uint16, int) {
	m.mu.Lock()
	m.sent++
	m.mu.Unlock()
}

func (m *metrics) get(f func(m *metrics) int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return f(m)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// listen joins a fresh test group. local is the socket's unicast
// endpoint on the loopback interface: the tests inject indications there,
// which needs no multicast support.
func listen(t *testing.T, opts ...routing.Option) (*routing.Conn, *metrics, netip.AddrPort, netip.AddrPort) {
	t.Helper()
	g := fakeknx.Group(t)
	m := &metrics{dropped: map[string]int{}}
	base := []routing.Option{routing.WithGroup(g.String()), routing.WithMetrics(m)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		// Send on the loopback interface, not on a physical network
		// (where macOS may block multicast writes).
		base = append(base, routing.WithInterface(lo))
	}
	c, err := routing.Listen(ctx(t), append(base, opts...)...)
	if err != nil {
		t.Skipf("cannot join %s: %v", g, err)
	}
	t.Cleanup(func() { c.Close() })
	return c, m, g, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), g.Port())
}

func frame(v byte) *cemi.LData {
	tpdu, _ := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{v}})
	return cemi.NewGroupFrame(cemi.LDataInd, knx.MustParseIndividualAddress("1.1.5"), ga, knx.PriorityLow, tpdu)
}

func encoded(t *testing.T, f cemi.Frame) []byte {
	t.Helper()
	b, err := cemi.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func receive(t *testing.T, c *routing.Conn) *cemi.LData {
	t.Helper()
	cx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	f, err := c.Receive(cx)
	if err != nil {
		t.Fatal(err)
	}
	return f.(*cemi.LData)
}

func TestListenErrors(t *testing.T) {
	leak.Check(t)
	for name, opts := range map[string][]routing.Option{
		"rate":      {routing.WithRate(-1)},
		"queue":     {routing.WithQueueSize(0)},
		"ttl":       {routing.WithTTL(0)},
		"group":     {routing.WithGroup("10.0.0.1:3671")},
		"port":      {routing.WithGroup("239.1.1.1:x")},
		"interface": {routing.WithInterface("no-such-interface0")},
	} {
		if _, err := routing.Listen(ctx(t), opts...); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReceive(t *testing.T) {
	leak.Check(t)
	c, m, g, local := listen(t, routing.WithLogger(nil), routing.WithMetrics(nil), routing.WithTTL(1), routing.WithLogger(knx.NopLogger()))
	_ = m
	if c.Group() != g {
		t.Fatalf("group %s", c.Group())
	}
	p := fakeknx.Listen(t)
	p.Send(local, &knxnetip.RoutingIndication{CEMI: encoded(t, frame(1))})
	if f := receive(t, c); f.TPDU[len(f.TPDU)-1] != 1 {
		t.Fatalf("frame %v", f)
	}
	// System broadcasts are not delivered.
	p.Send(local, &knxnetip.RoutingIndication{SystemBroadcast: true, CEMI: encoded(t, frame(2))})
	p.Send(local, &knxnetip.RoutingIndication{CEMI: encoded(t, frame(3))})
	if f := receive(t, c); f.TPDU[len(f.TPDU)-1] != 3 {
		t.Fatalf("frame %v", f)
	}
}

func TestReceiveErrorsAndQueue(t *testing.T) {
	leak.Check(t)
	c, m, _, local := listen(t, routing.WithQueueSize(1))
	p := fakeknx.Listen(t)
	p.SendRaw(local, []byte{1, 2, 3})
	p.Send(local, &knxnetip.RoutingIndication{CEMI: []byte{0x29, 0x00}})
	p.Send(local, &knxnetip.SearchRequest{Discovery: p.HPAI()}) // ignored
	p.Send(local, &knxnetip.RoutingIndication{CEMI: encoded(t, frame(1))})
	p.Send(local, &knxnetip.RoutingIndication{CEMI: encoded(t, frame(2))})
	eventually(t, "metrics", func() bool {
		return m.get(func(m *metrics) int { return m.decode }) == 2 && m.get(func(m *metrics) int { return m.dropped["queue_full"] }) == 1
	})
	if f := receive(t, c); f.TPDU[len(f.TPDU)-1] != 1 {
		t.Fatalf("frame %v", f)
	}
}

func TestSend(t *testing.T) {
	leak.Check(t)
	c, m, _, _ := listen(t)
	// L_Data.req is sent as L_Data.ind; the caller's frame is unchanged.
	req := frame(1)
	req.MsgCode = cemi.LDataReq
	if err := c.Send(ctx(t), req); err != nil {
		t.Fatal(err)
	}
	if req.MsgCode != cemi.LDataReq {
		t.Fatal("Send modified its argument")
	}
	if m.get(func(m *metrics) int { return m.sent }) != 1 {
		t.Fatal("not sent")
	}
	// Hop count 0 is refused.
	zero := frame(2)
	zero.SetHopCount(0)
	if err := c.Send(ctx(t), zero); !errors.Is(err, knx.ErrInvalidValue) {
		t.Fatalf("hop count 0: %v", err)
	}
	bad := frame(3)
	bad.TPDU = nil
	if err := c.Send(ctx(t), bad); err == nil {
		t.Fatal("invalid frame sent")
	}
	// Other frames are sent as they are.
	if err := c.Send(ctx(t), &cemi.Unknown{MsgCode: 0xFE, Data: []byte{1, 2}}); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimit(t *testing.T) {
	leak.Check(t)
	c, _, _, _ := listen(t, routing.WithRate(20))
	start := time.Now()
	for i := 0; i < 30; i++ { // a burst of 20, then 10 at 20/s
		if err := c.Send(ctx(t), frame(byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 400*time.Millisecond || d > 2*time.Second {
		t.Fatalf("30 sends at 20/s took %v, want about 500 ms", d)
	}
	// A context ends the wait.
	short, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	for {
		if err := c.Send(short, frame(0)); err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err %v", err)
			}
			break
		}
	}
	// No limit.
	u, _, _, _ := listen(t, routing.WithRate(0))
	start = time.Now()
	for i := 0; i < 200; i++ {
		if err := u.Send(ctx(t), frame(byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("unlimited sends took %v", d)
	}
}

func TestRoutingBusy(t *testing.T) {
	leak.Check(t)
	c, _, _, local := listen(t, routing.WithRate(0))
	p := fakeknx.Listen(t)
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 200})
	var ev routing.Event
	select {
	case ev = <-c.Events():
	case <-time.After(wait):
		t.Fatal("no busy event")
	}
	if ev.Busy == nil || ev.Busy.WaitTime != 200 || ev.From != p.Addr() || ev.Lost != nil {
		t.Fatalf("event %+v", ev)
	}
	start := time.Now()
	if err := c.Send(ctx(t), frame(1)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("Send during ROUTING_BUSY returned after %v", d)
	}
	// A shorter wait does not shorten a pending one; the wait can be
	// interrupted.
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 60000})
	<-c.Events()
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 1})
	<-c.Events()
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Send(short, frame(2)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send: %v", err)
	}
	// Close interrupts it too.
	errc := make(chan error, 1)
	go func() { errc <- c.Send(context.Background(), frame(3)) }()
	c.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, knx.ErrClosed) {
			t.Fatalf("Send after Close: %v", err)
		}
	case <-time.After(wait):
		t.Fatal("Send blocked after Close")
	}
}

func TestLostMessageAndEventOverflow(t *testing.T) {
	leak.Check(t)
	c, _, _, local := listen(t)
	p := fakeknx.Listen(t)
	p.Send(local, &knxnetip.RoutingLostMessage{Lost: 7, DeviceState: 1})
	select {
	case ev := <-c.Events():
		if ev.Lost == nil || ev.Lost.Lost != 7 {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(wait):
		t.Fatal("no event")
	}
	// The event channel is bounded: unread events are dropped, the
	// reader keeps going.
	for i := 0; i < 40; i++ {
		p.Send(local, &knxnetip.RoutingLostMessage{Lost: uint16(i)})
	}
	p.Send(local, &knxnetip.RoutingIndication{CEMI: encoded(t, frame(9))})
	if f := receive(t, c); f.TPDU[len(f.TPDU)-1] != 9 {
		t.Fatalf("frame %v", f)
	}
	if n := len(c.Events()); n != 16 {
		t.Fatalf("%d events buffered, want 16", n)
	}
}

func TestEchoSuppression(t *testing.T) {
	leak.Check(t)
	c, _, _, local := listen(t, routing.WithLoopback(true), routing.WithRate(0))
	p := fakeknx.Listen(t)
	f := frame(1)
	if err := c.Send(ctx(t), f); err != nil {
		t.Fatal(err)
	}
	echo, _ := knxnetip.Marshal(&knxnetip.RoutingIndication{CEMI: encoded(t, f)})
	if !fakeknx.MulticastWorks() {
		// What the system would loop back: the same datagram.
		p.SendRaw(local, echo)
	}
	// A marker after the echo: it must be the first frame delivered.
	p.Send(local, &knxnetip.RoutingIndication{CEMI: encoded(t, frame(2))})
	if got := receive(t, c); got.TPDU[len(got.TPDU)-1] != 2 {
		t.Fatalf("got %v, want the marker (own echo delivered?)", got)
	}
	// Each sent datagram suppresses one copy: a second copy is a
	// telegram of another router.
	p.SendRaw(local, echo)
	if got := receive(t, c); got.TPDU[len(got.TPDU)-1] != 1 {
		t.Fatalf("frame %v", got)
	}
}

func TestClose(t *testing.T) {
	leak.Check(t)
	c, _, _, _ := listen(t)
	errc := make(chan error, 1)
	go func() { _, err := c.Receive(context.Background()); errc <- err }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("Receive: %v", err)
	}
	if err := c.Send(ctx(t), frame(1)); err == nil {
		t.Fatal("Send after Close succeeded")
	}
	cx, cancel := context.WithCancel(context.Background())
	cancel()
	c2, _, _, _ := listen(t)
	if _, err := c2.Receive(cx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive: %v", err)
	}
}

func TestInterface(t *testing.T) {
	leak.Check(t)
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 && i.Flags&net.FlagMulticast != 0 {
			c, _, _, _ := listen(t, routing.WithInterface(i.Name))
			if err := c.Send(ctx(t), frame(1)); err != nil {
				t.Logf("send on %s: %v", i.Name, err)
			}
			return
		}
	}
	t.Skip("no multicast loopback interface")
}

// TestMulticast needs IP multicast: two Conns on the same host with
// loopback hear each other, not themselves.
func TestMulticast(t *testing.T) {
	fakeknx.RequireMulticast(t)
	leak.Check(t)
	a, _, g, _ := listen(t, routing.WithLoopback(true), routing.WithRate(0))
	opts := []routing.Option{routing.WithGroup(g.String()), routing.WithLoopback(true)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		opts = append(opts, routing.WithInterface(lo))
	}
	b, err := routing.Listen(ctx(t), opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := a.Send(ctx(t), frame(1)); err != nil {
		t.Fatal(err)
	}
	if f := receive(t, b); f.TPDU[len(f.TPDU)-1] != 1 {
		t.Fatalf("b got %v", f)
	}
	cx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if f, err := a.Receive(cx); err == nil {
		t.Fatalf("a heard its own echo: %v", f)
	}
}
