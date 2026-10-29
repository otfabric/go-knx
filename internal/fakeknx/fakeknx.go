// SPDX-License-Identifier: MIT

// Package fakeknx is a scriptable fake KNXnet/IP peer for tests: a UDP
// socket on the loopback interface that queues the KNXnet/IP messages it
// receives, lets a test answer them one by one, and can answer some of
// them automatically. It also holds the multicast availability check
// shared by the tests that need IP multicast.
package fakeknx

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/mcast"
	"github.com/otfabric/go-knx/knxnetip"
)

// Datagram is a message the peer received.
type Datagram struct {
	From netip.AddrPort
	Msg  knxnetip.Message
	Raw  []byte
}

// Handler answers a datagram automatically; it returns true when the
// datagram is consumed (not queued).
type Handler func(p *Peer, d Datagram) bool

// Peer is a fake KNXnet/IP endpoint.
type Peer struct {
	t    testing.TB
	conn *net.UDPConn
	in   chan Datagram

	mu       sync.Mutex
	handlers []Handler
	done     chan struct{}
}

// Listen opens a peer on 127.0.0.1 with an ephemeral port; it is closed
// when the test ends.
func Listen(t testing.TB) *Peer { return ListenAddr(t, "127.0.0.1:0") }

// ListenAddr opens a peer on addr.
func ListenAddr(t testing.TB, addr string) *Peer {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp4", ua)
	if err != nil {
		t.Fatal(err)
	}
	p := &Peer{t: t, conn: c, in: make(chan Datagram, 1024), done: make(chan struct{})}
	go p.read()
	t.Cleanup(p.Close)
	return p
}

// Close closes the socket and waits for the reader.
func (p *Peer) Close() {
	_ = p.conn.Close()
	<-p.done
}

// Addr returns the local endpoint.
func (p *Peer) Addr() netip.AddrPort {
	ap := p.conn.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// String returns the local endpoint as "127.0.0.1:port".
func (p *Peer) String() string { return p.Addr().String() }

// HPAI returns the peer's endpoint as an HPAI.
func (p *Peer) HPAI() knxnetip.HPAI { return knxnetip.NewHPAI(p.Addr()) }

// Handle adds an automatic handler; handlers run in the reader goroutine
// in the order they were added.
func (p *Peer) Handle(h Handler) {
	p.mu.Lock()
	p.handlers = append(p.handlers, h)
	p.mu.Unlock()
}

func (p *Peer) read() {
	defer close(p.done)
	buf := make([]byte, 2048)
	for {
		n, from, err := p.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		raw := append([]byte(nil), buf[:n]...)
		m, err := knxnetip.Parse(raw)
		if err != nil {
			continue
		}
		d := Datagram{From: netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), Msg: m, Raw: raw}
		p.mu.Lock()
		hs := append([]Handler(nil), p.handlers...)
		p.mu.Unlock()
		consumed := false
		for _, h := range hs {
			if h(p, d) {
				consumed = true
				break
			}
		}
		if !consumed {
			select {
			case p.in <- d:
			default:
			}
		}
	}
}

// Send sends a message to to.
func (p *Peer) Send(to netip.AddrPort, m knxnetip.Message) {
	b, err := knxnetip.Marshal(m)
	if err != nil {
		p.t.Errorf("fakeknx: marshal %s: %v", m.Service(), err)
		return
	}
	p.SendRaw(to, b)
}

// SendRaw sends raw octets to to.
func (p *Peer) SendRaw(to netip.AddrPort, b []byte) {
	if _, err := p.conn.WriteToUDPAddrPort(b, to); err != nil && !errors.Is(err, net.ErrClosed) {
		p.t.Errorf("fakeknx: write to %s: %v", to, err)
	}
}

// Next returns the next queued datagram, waiting up to d.
func (p *Peer) Next(d time.Duration) (Datagram, bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case x := <-p.in:
		return x, true
	case <-t.C:
		return Datagram{}, false
	}
}

// Expect returns the next queued datagram of type T, skipping others,
// and fails the test if none arrives within d.
func Expect[T knxnetip.Message](p *Peer, d time.Duration) (T, Datagram) {
	p.t.Helper()
	deadline := time.Now().Add(d)
	for {
		x, ok := p.Next(time.Until(deadline))
		if !ok {
			var zero T
			p.t.Fatalf("fakeknx: no %T within %v", zero, d)
			return zero, Datagram{}
		}
		if m, ok := x.Msg.(T); ok {
			return m, x
		}
	}
}

// ExpectNone fails the test if a datagram of type T arrives within d.
func ExpectNone[T knxnetip.Message](p *Peer, d time.Duration) {
	p.t.Helper()
	deadline := time.Now().Add(d)
	for {
		x, ok := p.Next(time.Until(deadline))
		if !ok {
			return
		}
		if _, ok := x.Msg.(T); ok {
			p.t.Fatalf("fakeknx: unexpected %s from %s", x.Msg.Service(), x.From)
		}
	}
}

// AnswerDisconnect is a handler that answers DISCONNECT_REQUESTs.
func AnswerDisconnect(p *Peer, d Datagram) bool {
	if m, ok := d.Msg.(*knxnetip.DisconnectRequest); ok {
		p.Send(d.From, &knxnetip.DisconnectResponse{Channel: m.Channel})
		return true
	}
	return false
}

// AnswerConnectionState is a handler that answers CONNECTIONSTATE_REQUESTs
// with E_NO_ERROR.
func AnswerConnectionState(p *Peer, d Datagram) bool {
	if m, ok := d.Msg.(*knxnetip.ConnectionStateRequest); ok {
		p.Send(d.From, &knxnetip.ConnectionStateResponse{Channel: m.Channel})
		return true
	}
	return false
}

// Confirmation returns the L_Data.con of an L_Data.req carried in a
// TUNNELLING_REQUEST, with the confirm error bit set when failed.
func Confirmation(req []byte, failed bool) []byte {
	f, err := cemi.Parse(req)
	if err != nil {
		panic(err)
	}
	ld := f.(*cemi.LData).Clone()
	ld.MsgCode = cemi.LDataCon
	if failed {
		ld.Ctrl1 |= cemi.Ctrl1ConfirmError
	}
	b, err := cemi.Marshal(ld)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	mcOnce sync.Once
	mcErr  error
)

// MulticastWorks reports whether IPv4 multicast with loopback works on
// this machine.
func MulticastWorks() bool {
	mcOnce.Do(func() { mcErr = probeMulticast() })
	return mcErr == nil
}

// RequireMulticast skips the test when IPv4 multicast with loopback does
// not work on this machine, or fails it when the environment variable
// KNX_REQUIRE_MULTICAST=1 is set (CI).
func RequireMulticast(t testing.TB) {
	t.Helper()
	mcOnce.Do(func() { mcErr = probeMulticast() })
	if mcErr == nil {
		return
	}
	if os.Getenv("KNX_REQUIRE_MULTICAST") == "1" {
		t.Fatalf("multicast is required (KNX_REQUIRE_MULTICAST=1) but does not work: %v", mcErr)
	}
	t.Skipf("multicast loopback does not work on this machine (%v); set KNX_REQUIRE_MULTICAST=1 to fail instead", mcErr)
}

// Group returns a fresh administratively scoped multicast group and port
// for a test, so that tests do not hear each other or real KNX routers.
func Group(t testing.TB) netip.AddrPort {
	t.Helper()
	port := FreePort(t)
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{239, 255, byte(port >> 8), byte(port)}), port)
}

// FreePort returns a UDP port that was free a moment ago.
func FreePort(t testing.TB) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// MulticastInterface returns the name of the loopback interface when it
// supports multicast (macOS, BSD), so that tests send multicast there and
// not on a physical network, or "" (Linux: the system's choice).
func MulticastInterface() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 && i.Flags&net.FlagMulticast != 0 && i.Flags&net.FlagUp != 0 {
			return i.Name
		}
	}
	return ""
}

func probeMulticast() error {
	if runtime.GOOS == "windows" {
		// Windows runners pass a one-datagram probe but lose the
		// loopback copies under load: the multicast tests run on Linux
		// and macOS.
		return errors.New("multicast loopback tests are not run on Windows")
	}
	tmp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return err
	}
	port := uint16(tmp.LocalAddr().(*net.UDPAddr).Port)
	_ = tmp.Close()
	group := netip.AddrPortFrom(netip.AddrFrom4([4]byte{239, 255, 77, 1}), port)
	var ifi *net.Interface
	if name := MulticastInterface(); name != "" {
		if ifi, err = net.InterfaceByName(name); err != nil {
			return err
		}
	}
	r, err := mcast.Listen(ifi, group, true, 1)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	s, err := mcast.Listen(ifi, group, true, 1)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	if ifi != nil {
		lo := netip.MustParseAddr("127.0.0.1")
		_ = mcast.Configure(s, &lo, true, 1)
	}
	_ = s.SetWriteDeadline(time.Now().Add(time.Second))
	msg := []byte("knx-multicast-probe")
	_ = r.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 3; i++ {
		if _, err := s.WriteToUDPAddrPort(msg, group); err != nil {
			return fmt.Errorf("send to %s: %w", group, err)
		}
	}
	buf := make([]byte, 64)
	for {
		n, _, err := r.ReadFromUDPAddrPort(buf)
		if err != nil {
			return fmt.Errorf("no multicast loopback on %s: %w", group, err)
		}
		if string(buf[:n]) == string(msg) {
			return nil
		}
	}
}
