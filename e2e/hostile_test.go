// SPDX-License-Identifier: MIT

package e2e

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// The hostile peer tests drive the server and the client with frames no
// well-behaved peer sends. The server must answer its other clients
// afterwards, free what a half-open peer holds, refuse what it must
// refuse; the client must fail with an error within its context.

var loopback = netip.MustParseAddr("127.0.0.1")

func udpSocket(t *testing.T, ip netip.Addr) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func localAddr(c *net.UDPConn) netip.AddrPort {
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// localOnly reports whether every HPAI of a datagram that decodes points
// at the loopback interface or asks for route back: random octets must not
// make the server send to arbitrary hosts.
func localOnly(b []byte) bool {
	m, err := knxnetip.Parse(b)
	if err != nil {
		return true
	}
	v := reflect.ValueOf(m)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return true
	}
	v = v.Elem()
	for _, field := range v.Fields() {
		if h, ok := field.Interface().(knxnetip.HPAI); ok {
			if a := h.Addr.Addr(); a.IsValid() && !a.IsLoopback() && !a.IsUnspecified() {
				return false
			}
		}
	}
	return true
}

// channelFrame reports whether a datagram decodes to a frame of a
// tunnelling channel: noise from 127.0.0.1 may hit a channel of a client on
// the same address, which the server cannot tell apart (see
// TestHostileSpoofedChannelFrames).
func channelFrame(b []byte) bool {
	m, err := knxnetip.Parse(b)
	if err != nil {
		return false
	}
	switch m.(type) {
	case *knxnetip.TunnellingRequest, *knxnetip.TunnellingAck, *knxnetip.DisconnectRequest,
		*knxnetip.ConnectionStateRequest, *knxnetip.DeviceConfigurationRequest, *knxnetip.DeviceConfigurationAck,
		*knxnetip.TunnellingFeature:
		return true
	}
	return false
}

// describeEventually checks that the server answers a description
// request, with retries (a flood may have overrun the socket buffers).
func describeEventually(t *testing.T, addr string) {
	t.Helper()
	var err error
	for range 10 {
		c, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_, err = discovery.Describe(c, addr)
		cancel()
		if err == nil {
			return
		}
	}
	t.Fatalf("the server does not answer DESCRIPTION_REQUEST: %v", err)
}

func eventually(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// noise returns n seeded random datagrams, half with a KNXnet/IP header
// in front, and the malformed frames of the size and length checks.
func noise(seed uint64, n int) [][]byte {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	var out [][]byte
	for i := range n {
		b := make([]byte, rng.IntN(80))
		for j := range b {
			b[j] = byte(rng.Uint32())
		}
		if i%2 == 0 && len(b) >= 6 {
			b[0], b[1] = 0x06, 0x10
			if i%4 == 0 {
				b[4], b[5] = byte(len(b)>>8), byte(len(b))
			}
		}
		out = append(out, b)
	}
	valid, _ := knxnetip.Marshal(&knxnetip.DescriptionRequest{Control: knxnetip.RouteBackHPAI()})
	lie := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), valid...)) }
	big := make([]byte, 1500)
	copy(big, []byte{0x06, 0x10, 0x02, 0x03, 0x05, 0xdc})
	huge := make([]byte, 8000)
	copy(huge, []byte{0x06, 0x10, 0x02, 0x03, 0x1f, 0x40})
	out = append(out,
		nil, // 0 octets
		[]byte{0x06},
		[]byte{0x06, 0x10, 0x02, 0x03, 0x00, 0x00},                  // length 0
		[]byte{0x06, 0x10, 0x02, 0x03, 0xff, 0xff},                  // claims 65535
		lie(func(b []byte) []byte { b[5] += 4; return b }),          // claims more than it carries
		lie(func(b []byte) []byte { b[5] -= 4; return b }),          // claims less
		lie(func(b []byte) []byte { b[0] = 0x07; return b }),        // header length 7
		lie(func(b []byte) []byte { b[1] = 0x20; return b }),        // version 2.0
		lie(func(b []byte) []byte { return b[:len(b)-1] }),          // truncated
		lie(func(b []byte) []byte { return append(b, 0xde, 0xad) }), // trailing octets
		lie(func(b []byte) []byte { b[6] = 0xff; return b }),        // HPAI length 255
		lie(func(b []byte) []byte { b[6] = 0x00; return b }),        // HPAI length 0
		big,  // more than MaxFrameLen, header consistent
		huge, // far more than MaxFrameLen
	)
	return out
}

// TestHostileNoise: random and malformed datagrams from a third socket do
// not disturb the server or a connected client.
func TestHostileNoise(t *testing.T) {
	leak.Check(t)
	s, addr := startServer(t)
	srv := netip.MustParseAddrPort(addr)
	c := ctx(t)
	cl, err := client.DialTunnel(c, addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	g := knx.MustParseGroupAddress("1/2/3")
	if err := cl.GroupWrite(c, g, true); err != nil {
		t.Fatal(err)
	}
	h := udpSocket(t, loopback)
	sent := 0
	for _, b := range noise(1, 500) {
		if !localOnly(b) || channelFrame(b) {
			continue
		}
		if _, err := h.WriteToUDPAddrPort(b, srv); err != nil {
			t.Fatalf("send %d octets: %v", len(b), err)
		}
		sent++
	}
	if sent < 400 {
		t.Fatalf("only %d datagrams sent", sent)
	}
	describeEventually(t, addr)
	if err := cl.GroupWrite(c, g, false); err != nil {
		t.Fatalf("group write after the noise: %v", err)
	}
	if n := len(s.Connections()); n > 2 {
		t.Fatalf("%d connections after the noise", n)
	}
}

// TestHostileConnectFlood: half-open peers flood CONNECT_REQUESTs. They
// may take the free tunnelling slots, but a connected client keeps its
// own, and the slots of peers that never send a heartbeat are reclaimed
// after the connection alive time.
func TestHostileConnectFlood(t *testing.T) {
	leak.Check(t)
	const alive = 500 * time.Millisecond
	s, addr := startServer(t, server.WithConnectionAliveTime(alive))
	srv := netip.MustParseAddrPort(addr)
	c := ctx(t)
	a, err := tunnel.Dial(c, addr, tunnel.WithHeartbeat(100*time.Millisecond, 300*time.Millisecond, 3))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	var flooders []*net.UDPConn
	for range 20 {
		flooders = append(flooders, udpSocket(t, loopback))
	}
	flood := func() {
		for range 25 {
			for _, f := range flooders {
				b, _ := knxnetip.Marshal(&knxnetip.ConnectRequest{Control: knxnetip.NewHPAI(localAddr(f)), Data: knxnetip.NewHPAI(localAddr(f)),
					CRI: knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)})
				_, _ = f.WriteToUDPAddrPort(b, srv)
			}
		}
	}
	// 500 datagrams in a burst can overrun the socket buffer: repeat
	// until a flooder holds the second slot.
	for range 10 {
		flood()
		if len(s.Connections()) == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(s.Connections()); n != 2 {
		t.Fatalf("%d connections during the flood, want 2", n)
	}
	// A new client finds no slot while flooders hold it: the flood goes
	// on, so that another flooder takes the slot when one expires.
	stop := make(chan struct{})
	var fwg sync.WaitGroup
	fwg.Go(func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			for _, f := range flooders {
				b, _ := knxnetip.Marshal(&knxnetip.ConnectRequest{Control: knxnetip.NewHPAI(localAddr(f)), Data: knxnetip.NewHPAI(localAddr(f)),
					CRI: knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)})
				_, _ = f.WriteToUDPAddrPort(b, srv)
			}
		}
	})
	var busy error
	for range 3 {
		var b *tunnel.Conn
		b, busy = tunnel.Dial(c, addr, tunnel.WithConnectTimeout(500*time.Millisecond))
		if b != nil {
			b.Close()
			close(stop)
			fwg.Wait()
			t.Fatal("a new client got a slot during the flood")
		}
		if !errors.Is(busy, knx.ErrTimeout) {
			break
		}
	}
	close(stop)
	fwg.Wait()
	if !errors.Is(busy, knx.ErrBusy) {
		t.Fatalf("connect during the flood: %v", busy)
	}
	// The flooder never sends a heartbeat: its slot is reclaimed.
	eventually(t, 3*time.Second, "the server to drop the half-open connection", func() bool { return len(s.Connections()) == 1 })
	if a.State() != knx.StateConnected || s.Connections()[0].Address != a.IndividualAddress() {
		t.Fatalf("the legitimate client lost its slot: %s, %+v", a.State(), s.Connections())
	}
	b, err := client.DialTunnel(c, addr, nil)
	if err != nil {
		t.Fatalf("connect after the flood: %v", err)
	}
	defer b.Close()
	if err := b.GroupWrite(c, knx.MustParseGroupAddress("1/2/3"), true); err != nil {
		t.Fatal(err)
	}
}

// rawTunnel is a hand-driven tunnelling client on a fakeknx peer that
// acknowledges the server's requests.
type rawTunnel struct {
	p   *fakeknx.Peer
	srv netip.AddrPort
	ch  uint8
	// ack turns the automatic acknowledgement of server requests off.
	noAck atomic.Bool
	reqs  chan *knxnetip.TunnellingRequest
}

func dialRawTunnel(t *testing.T, addr string) *rawTunnel {
	t.Helper()
	r := &rawTunnel{p: fakeknx.Listen(t), srv: netip.MustParseAddrPort(addr), reqs: make(chan *knxnetip.TunnellingRequest, 64)}
	r.p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		m, ok := d.Msg.(*knxnetip.TunnellingRequest)
		if !ok {
			return false
		}
		if !r.noAck.Load() {
			p.Send(d.From, &knxnetip.TunnellingAck{Channel: m.Channel, Seq: m.Seq})
		}
		select {
		case r.reqs <- m:
		default:
		}
		return true
	})
	for attempt := 0; ; attempt++ {
		r.p.Send(r.srv, &knxnetip.ConnectRequest{Control: r.p.HPAI(), Data: r.p.HPAI(), CRI: knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)})
		x, ok := r.p.Next(time.Second)
		if !ok {
			if attempt < 3 {
				continue
			}
			t.Fatal("no CONNECT_RESPONSE")
		}
		resp, ok := x.Msg.(*knxnetip.ConnectResponse)
		if !ok || resp.Status != knxnetip.StatusNoError {
			t.Fatalf("connect: %+v", x.Msg)
		}
		r.ch = resp.Channel
		return r
	}
}

func groupWriteCEMI(t *testing.T, v byte) []byte {
	t.Helper()
	b, err := cemi.Marshal(cemi.NewGroupFrame(cemi.LDataReq, 0, knx.MustParseGroupAddress("1/2/3"), knx.PriorityLow, []byte{0x00, 0x80, v}))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// request sends a TUNNELLING_REQUEST and reports whether the server
// acknowledged it (retrying the send, as a client repeats a request).
func (r *rawTunnel) request(t *testing.T, ch, seq uint8, cemiFrame []byte, attempts int) bool {
	t.Helper()
	for range attempts {
		r.p.Send(r.srv, &knxnetip.TunnellingRequest{Channel: ch, Seq: seq, CEMI: cemiFrame})
		deadline := time.Now().Add(300 * time.Millisecond)
		for {
			x, ok := r.p.Next(time.Until(deadline))
			if !ok {
				break
			}
			if a, ok := x.Msg.(*knxnetip.TunnellingAck); ok && a.Channel == ch && a.Seq == seq {
				return true
			}
		}
	}
	return false
}

// TestHostileSequence: the server's receive window. A repeated request is
// acknowledged but not delivered again; a request out of the window and
// one on another channel are neither acknowledged nor delivered.
func TestHostileSequence(t *testing.T) {
	leak.Check(t)
	s, addr := startServer(t)
	var mu sync.Mutex
	got := map[byte]int{}
	cancel := s.Subscribe(func(tg server.Telegram) {
		if tg.Origin != server.FromTunnel || len(tg.Frame.TPDU) < 3 {
			return
		}
		mu.Lock()
		got[tg.Frame.TPDU[2]]++
		mu.Unlock()
	})
	defer cancel()
	count := func(v byte) int { mu.Lock(); defer mu.Unlock(); return got[v] }
	r := dialRawTunnel(t, addr)

	if !r.request(t, r.ch, 0, groupWriteCEMI(t, 1), 5) {
		t.Fatal("sequence 0 not acknowledged")
	}
	eventually(t, 2*time.Second, "delivery of sequence 0", func() bool { return count(1) == 1 })
	// The repetition of sequence 0 (its ACK lost) is acknowledged again.
	if !r.request(t, r.ch, 0, groupWriteCEMI(t, 1), 5) {
		t.Fatal("the repetition of sequence 0 not acknowledged")
	}
	// Out of the window, and on another channel: no ACK.
	if r.request(t, r.ch, 5, groupWriteCEMI(t, 5), 1) {
		t.Error("sequence 5 acknowledged while 1 is expected")
	}
	if r.request(t, r.ch, 0xFF, groupWriteCEMI(t, 6), 1) {
		t.Error("sequence 255 acknowledged while 1 is expected")
	}
	if r.request(t, r.ch+1, 1, groupWriteCEMI(t, 7), 1) {
		t.Error("request on a channel that does not exist acknowledged")
	}
	if !r.request(t, r.ch, 1, groupWriteCEMI(t, 2), 5) {
		t.Fatal("sequence 1 not acknowledged")
	}
	eventually(t, 2*time.Second, "delivery of sequence 1", func() bool { return count(2) == 1 })
	time.Sleep(100 * time.Millisecond)
	for v, want := range map[byte]int{1: 1, 2: 1, 5: 0, 6: 0, 7: 0} {
		if n := count(v); n != want {
			t.Errorf("value %d delivered %d times, want %d", v, n, want)
		}
	}
}

// spoofCase sets up a raw client that does not acknowledge, makes the
// server send it a request, and lets spoof act from another socket; it
// reports whether the server took the spoofed frame as the client's.
func spoofAckAccepted(t *testing.T, from netip.Addr) bool {
	t.Helper()
	_, addr := startServer(t, server.WithRequestTimeout(200*time.Millisecond))
	r := dialRawTunnel(t, addr)
	r.noAck.Store(true)
	w, err := client.DialTunnel(ctx(t), addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.GroupWrite(ctx(t), knx.MustParseGroupAddress("1/2/3"), true); err != nil {
		t.Fatal(err)
	}
	var first *knxnetip.TunnellingRequest
	select {
	case first = <-r.reqs:
	case <-time.After(2 * time.Second):
		t.Fatal("the server sent the raw client nothing")
	}
	h := udpSocket(t, from)
	b, _ := knxnetip.Marshal(&knxnetip.TunnellingAck{Channel: r.ch, Seq: first.Seq})
	if _, err := h.WriteToUDPAddrPort(b, netip.MustParseAddrPort(addr)); err != nil {
		t.Fatal(err)
	}
	// The server repeats an unacknowledged request after its request
	// timeout (200 ms): a repetition means the spoofed ACK was refused.
	deadline := time.After(time.Second)
	for {
		select {
		case again := <-r.reqs:
			if again.Seq == first.Seq {
				return false
			}
		case <-deadline:
			return true
		}
	}
}

// TestHostileSpoofedChannelFrames: frames of a client's channel sent from
// another socket. From another address they must be refused. From another
// port of the client's address the server cannot be fooled either when the
// client did not ask for route back (the data endpoint is known).
func TestHostileSpoofedChannelFrames(t *testing.T) {
	t.Run("ack from another address", func(t *testing.T) {
		other := netip.MustParseAddr("127.0.0.2")
		if c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(other, 0))); err != nil {
			t.Skipf("127.0.0.2 is not usable on this machine (%v); Linux has the whole 127/8 on loopback", err)
		} else {
			_ = c.Close()
		}
		leak.Check(t)
		if spoofAckAccepted(t, other) {
			t.Fatal("the server took a TUNNELLING_ACK from 127.0.0.2 for a client on 127.0.0.1")
		}
	})
	t.Run("ack from another port", func(t *testing.T) {
		leak.Check(t)
		if spoofAckAccepted(t, loopback) {
			t.Fatal("the server took a TUNNELLING_ACK for a channel from another port of the client's address")
		}
	})
	t.Run("disconnect from another port", func(t *testing.T) {
		leak.Check(t)
		s, addr := startServer(t)
		r := dialRawTunnel(t, addr)
		h := udpSocket(t, loopback)
		b, _ := knxnetip.Marshal(&knxnetip.DisconnectRequest{Channel: r.ch, Control: knxnetip.NewHPAI(localAddr(h))})
		if _, err := h.WriteToUDPAddrPort(b, netip.MustParseAddrPort(addr)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if len(s.Connections()) == 0 {
			t.Fatal("the server took a DISCONNECT_REQUEST for a channel from another port of the client's address")
		}
	})
}

// TestHostileTCP: a TCP peer that claims more than a frame may hold is
// closed at once; one that stalls in a frame holds one connection until
// the alive time and blocks nobody; peers that take every TCP connection
// lose them after the alive time.
func TestHostileTCP(t *testing.T) {
	leak.Check(t)
	const alive = 600 * time.Millisecond
	_, addr := startServer(t, server.WithConnectionAliveTime(alive))
	dial := func() *net.TCPConn {
		c, err := net.DialTCP("tcp4", nil, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	closedWithin := func(c *net.TCPConn, d time.Duration) bool {
		_ = c.SetReadDeadline(time.Now().Add(d))
		_, err := io.Copy(io.Discard, c)
		var ne net.Error
		return !errors.As(err, &ne) || !ne.Timeout()
	}

	// A header that claims 65535 octets: refused before any body is
	// read (MaxFrameLen), not after waiting for 64 KiB.
	claim := dial()
	start := time.Now()
	if _, err := claim.Write([]byte{0x06, 0x10, 0x02, 0x03, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}
	if !closedWithin(claim, alive/2) {
		t.Fatalf("a 65535-octet claim kept the connection open for %v", time.Since(start))
	}
	// A frame of 1000 octets that stops after 10.
	stall := dial()
	if _, err := stall.Write([]byte{0x06, 0x10, 0x02, 0x03, 0x03, 0xe8, 0x08, 0x01, 0x7f, 0x00}); err != nil {
		t.Fatal(err)
	}
	c := ctx(t)
	cl, err := client.DialTunnel(c, addr, []tunnel.Option{tunnel.WithTCP()})
	if err != nil {
		t.Fatalf("TCP client beside a stalled one: %v", err)
	}
	if err := cl.GroupWrite(c, knx.MustParseGroupAddress("1/2/3"), true); err != nil {
		t.Fatalf("group write beside a stalled TCP peer: %v", err)
	}
	cl.Close()
	if !closedWithin(stall, 3*alive) {
		t.Fatal("the stalled TCP peer was not closed after the alive time")
	}

	// Two tunnelling addresses: at most 6 TCP connections. Stalled peers
	// that take them all lock other clients out until the alive time.
	for range 6 {
		if _, err := dial().Write([]byte{0x06, 0x10}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	refused := dial()
	if !closedWithin(refused, alive/2) {
		t.Error("a seventh TCP connection was kept")
	}
	var lastErr error
	deadline := time.Now().Add(3 * alive)
	for time.Now().Before(deadline) {
		var cl *client.Client
		dc, cancel := context.WithTimeout(c, 300*time.Millisecond)
		cl, lastErr = client.DialTunnel(dc, addr, []tunnel.Option{tunnel.WithTCP(), tunnel.WithConnectTimeout(300 * time.Millisecond)})
		cancel()
		if lastErr == nil {
			cl.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the TCP connections of stalled peers were not reclaimed: %v", lastErr)
}

// secureSession is a hand-driven KNX IP Secure session over UDP.
type secureSession struct {
	t    *testing.T
	p    *fakeknx.Peer
	srv  netip.AddrPort
	kp   *secure.KeyPair
	resp *knxnetip.SessionResponse
	sess *secure.Session
}

func openSession(t *testing.T, addr string) *secureSession {
	t.Helper()
	kp, err := secure.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ss := &secureSession{t: t, p: fakeknx.Listen(t), srv: netip.MustParseAddrPort(addr), kp: kp}
	for attempt := 0; ; attempt++ {
		ss.p.Send(ss.srv, &knxnetip.SessionRequest{Control: ss.p.HPAI(), PublicKey: kp.Public})
		x, ok := ss.p.Next(time.Second)
		if !ok {
			if attempt < 3 {
				continue
			}
			t.Fatal("no SESSION_RESPONSE")
		}
		resp, ok := x.Msg.(*knxnetip.SessionResponse)
		if !ok {
			t.Fatalf("answer %s", x.Msg.Service())
		}
		ss.resp = resp
		break
	}
	key, err := kp.SessionKey(ss.resp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ss.sess = secure.NewSession(ss.resp.SessionID, key, [6]byte{0, 0xfa, 1, 2, 3, 4})
	return ss
}

// wrap returns m in the session's next SECURE_WRAPPER.
func (ss *secureSession) wrap(m knxnetip.Message) []byte {
	ss.t.Helper()
	b, err := ss.sess.Marshal(m)
	if err != nil {
		ss.t.Fatal(err)
	}
	return b
}

func (ss *secureSession) auth(user uint8, password string) []byte {
	ss.t.Helper()
	k, err := secure.UserPasswordKey(password)
	if err != nil {
		ss.t.Fatal(err)
	}
	return ss.wrap(&knxnetip.SessionAuthenticate{UserID: user, MAC: secure.AuthenticateMAC(k, user, ss.kp.Public, ss.resp.PublicKey)})
}

// next returns the next frame of the session within d, or nil.
func (ss *secureSession) next(d time.Duration) knxnetip.Message {
	ss.t.Helper()
	x, ok := ss.p.Next(d)
	if !ok {
		return nil
	}
	w, ok := x.Msg.(*knxnetip.SecureWrapper)
	if !ok {
		ss.t.Fatalf("plain %s in a secure session", x.Msg.Service())
	}
	frame, err := ss.sess.Unwrap(w)
	if err != nil {
		ss.t.Fatalf("the server's wrapper: %v", err)
	}
	m, err := knxnetip.Parse(frame)
	if err != nil {
		ss.t.Fatal(err)
	}
	return m
}

func (ss *secureSession) status(want knxnetip.SessionStatusCode) {
	ss.t.Helper()
	m := ss.next(time.Second)
	st, ok := m.(*knxnetip.SessionStatus)
	if !ok || st.Status != want {
		ss.t.Fatalf("answer %#v, want SESSION_STATUS %d", m, want)
	}
}

// TestHostileSecureSession: wrong user passwords, forged MACs, replays
// and frames of unknown sessions are refused without changing the
// session's state, and half-open sessions are reclaimed.
func TestHostileSecureSession(t *testing.T) {
	leak.Check(t)
	const alive = 500 * time.Millisecond
	dev, _ := secure.DeviceAuthenticationCode("trustme")
	u2, _ := secure.UserPasswordKey("secret2")
	users := map[uint8]server.SecureUser{2: {Key: u2}}
	// Sessions are idle between the frames of a subtest: a long alive time,
	// except for the server of the half-open sessions.
	s, addr := startServer(t, server.WithConnectionAliveTime(10*time.Second), server.WithSecure(dev, users))
	connect := func(ss *secureSession) []byte {
		return ss.wrap(&knxnetip.ConnectRequest{Control: ss.p.HPAI(), Data: ss.p.HPAI(), CRI: knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)})
	}

	t.Run("wrong password", func(t *testing.T) {
		ss := openSession(t, addr)
		ss.t = t
		ss.p.SendRaw(ss.srv, ss.auth(2, "wrong"))
		ss.status(knxnetip.SessionAuthFailed)
		ss.p.SendRaw(ss.srv, ss.auth(9, "secret2"))
		ss.status(knxnetip.SessionAuthFailed)
		ss.p.SendRaw(ss.srv, connect(ss))
		ss.status(knxnetip.SessionUnauthenticated)
		if n := len(s.Connections()); n != 0 {
			t.Fatalf("%d connections of an unauthenticated session", n)
		}
	})

	t.Run("forged and replayed wrappers", func(t *testing.T) {
		ss := openSession(t, addr)
		ss.t = t
		// A wrapper with a sequence far ahead under the wrong key must not
		// move the session's replay window.
		inner, _ := knxnetip.Marshal(&knxnetip.SessionStatus{Status: knxnetip.SessionClose})
		forged, err := secure.Seal(secure.Key{0xbad & 0xff}, ss.resp.SessionID, 1<<40, [6]byte{}, 0, inner)
		if err != nil {
			t.Fatal(err)
		}
		fb, _ := knxnetip.Marshal(forged)
		ss.p.SendRaw(ss.srv, fb)
		// A genuine wrapper with one octet of its MAC flipped.
		good := ss.auth(2, "secret2")
		bad := append([]byte(nil), good...)
		bad[len(bad)-1] ^= 0x01
		ss.p.SendRaw(ss.srv, bad)
		// An unknown session.
		other := append([]byte(nil), good...)
		other[6] ^= 0xff
		ss.p.SendRaw(ss.srv, other)
		if m := ss.next(300 * time.Millisecond); m != nil {
			t.Fatalf("answer to a forged wrapper: %#v", m)
		}
		ss.p.SendRaw(ss.srv, good)
		ss.status(knxnetip.SessionAuthSuccess)

		req := connect(ss)
		ss.p.SendRaw(ss.srv, req)
		resp, ok := ss.next(time.Second).(*knxnetip.ConnectResponse)
		if !ok || resp.Status != knxnetip.StatusNoError {
			t.Fatalf("connect in the session: %#v", resp)
		}
		ss.p.SendRaw(ss.srv, ss.wrap(&knxnetip.DisconnectRequest{Channel: resp.Channel, Control: ss.p.HPAI()}))
		if _, ok := ss.next(time.Second).(*knxnetip.DisconnectResponse); !ok {
			t.Fatal("no DISCONNECT_RESPONSE")
		}
		eventually(t, time.Second, "the disconnection", func() bool { return len(s.Connections()) == 0 })
		// The CONNECT_REQUEST again, verbatim: a replay.
		ss.p.SendRaw(ss.srv, req)
		ss.p.SendRaw(ss.srv, good)
		if m := ss.next(300 * time.Millisecond); m != nil {
			t.Fatalf("answer to a replayed wrapper: %#v", m)
		}
		if n := len(s.Connections()); n != 0 {
			t.Fatalf("a replayed CONNECT_REQUEST opened %d connections", n)
		}
		ss.p.SendRaw(ss.srv, ss.wrap(&knxnetip.SessionStatus{Status: knxnetip.SessionClose}))
	})

	t.Run("half-open sessions", func(t *testing.T) {
		// Two tunnelling addresses: at most 6 sessions over UDP. Peers
		// that open sessions and go silent hold them until the alive time.
		_, addr := startServer(t, server.WithConnectionAliveTime(alive), server.WithSecure(dev, users))
		for range 8 {
			kp, _ := secure.NewKeyPair()
			h := udpSocket(t, loopback)
			b, _ := knxnetip.Marshal(&knxnetip.SessionRequest{Control: knxnetip.NewHPAI(localAddr(h)), PublicKey: kp.Public})
			_, _ = h.WriteToUDPAddrPort(b, netip.MustParseAddrPort(addr))
		}
		cred, err := secure.NewCredentials(2, "secret2", "trustme")
		if err != nil {
			t.Fatal(err)
		}
		var lastErr error
		deadline := time.Now().Add(4 * alive)
		for time.Now().Before(deadline) {
			var c *tunnel.Conn
			dc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			c, lastErr = tunnel.Dial(dc, addr, tunnel.WithSecure(cred), tunnel.WithUDP(), tunnel.WithConnectTimeout(200*time.Millisecond))
			cancel()
			if lastErr == nil {
				c.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("no secure session after the half-open ones expired: %v", lastErr)
	})
}

// hostilePeer is a fake server whose answers a test scripts.
func hostilePeer(t *testing.T, answer func(p *fakeknx.Peer, d fakeknx.Datagram)) *fakeknx.Peer {
	t.Helper()
	p := fakeknx.Listen(t)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool { answer(p, d); return true })
	return p
}

// TestHostileServerDial: a server that answers CONNECT_REQUEST with
// garbage, a truncated response, a wrong CRD or a refusal makes Dial fail
// with an error within its connect timeout.
func TestHostileServerDial(t *testing.T) {
	ok, _ := knxnetip.Marshal(&knxnetip.ConnectResponse{Channel: 7, Data: knxnetip.RouteBackHPAI(),
		CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: 0x11ff}})
	truncated := append([]byte(nil), ok[:len(ok)-3]...)
	truncated[5] = byte(len(truncated)) // consistent header, short CRD
	rng := rand.New(rand.NewPCG(7, 7))
	for name, tc := range map[string]struct {
		answers func() [][]byte
		want    error
	}{
		"garbage": {func() [][]byte {
			var out [][]byte
			for _, b := range noise(rng.Uint64(), 20) {
				if !channelFrame(b) {
					out = append(out, b)
				}
			}
			return out
		}, knx.ErrTimeout},
		"truncated":     {func() [][]byte { return [][]byte{truncated, ok[:len(ok)-3]} }, knx.ErrTimeout},
		"header only":   {func() [][]byte { return [][]byte{ok[:6]} }, knx.ErrTimeout},
		"wrong service": {func() [][]byte { b := append([]byte(nil), ok...); b[3] = 0x08; return [][]byte{b} }, knx.ErrTimeout},
		"wrong CRD": {func() [][]byte {
			b, _ := knxnetip.Marshal(&knxnetip.ConnectResponse{Channel: 7, Data: knxnetip.RouteBackHPAI(), CRD: knxnetip.CRD{Type: knxnetip.DeviceManagementConnection}})
			return [][]byte{b}
		}, knx.ErrMalformed},
		"no more channels": {func() [][]byte {
			b, _ := knxnetip.Marshal(&knxnetip.ConnectResponse{Status: knxnetip.StatusNoMoreConnections})
			return [][]byte{b}
		}, knx.ErrBusy},
		"connection type": {func() [][]byte {
			b, _ := knxnetip.Marshal(&knxnetip.ConnectResponse{Status: knxnetip.StatusConnectionType})
			return [][]byte{b}
		}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			leak.Check(t)
			p := hostilePeer(t, func(p *fakeknx.Peer, d fakeknx.Datagram) {
				if _, isConnect := d.Msg.(*knxnetip.ConnectRequest); isConnect {
					for _, b := range tc.answers() {
						p.SendRaw(d.From, b)
					}
				}
			})
			c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			start := time.Now()
			conn, err := tunnel.Dial(c, p.String(), tunnel.WithConnectTimeout(300*time.Millisecond))
			if conn != nil {
				conn.Close()
				t.Fatal("connected to a hostile server")
			}
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("Dial: %v, want %v", err, tc.want)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("Dial took %v", d)
			}
		})
	}
}

// acceptOn7 answers CONNECT_REQUEST with channel 7 and the other frames
// with f.
func acceptOn7(t *testing.T, f func(p *fakeknx.Peer, d fakeknx.Datagram)) *fakeknx.Peer {
	return hostilePeer(t, func(p *fakeknx.Peer, d fakeknx.Datagram) {
		switch d.Msg.(type) {
		case *knxnetip.ConnectRequest:
			p.Send(d.From, &knxnetip.ConnectResponse{Channel: 7, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: 0x11ff}})
		case *knxnetip.DisconnectRequest:
			p.Send(d.From, &knxnetip.DisconnectResponse{Channel: 7})
		default:
			f(p, d)
		}
	})
}

// TestHostileServerTunnel: a server that acknowledges on the wrong
// channel or not at all, and one that floods the client with requests,
// make the client's sends fail with errors within their contexts; the
// client closes cleanly.
func TestHostileServerTunnel(t *testing.T) {
	ld := cemi.NewGroupFrame(cemi.LDataReq, 0, knx.MustParseGroupAddress("1/2/3"), knx.PriorityLow, []byte{0x00, 0x81})
	opts := []tunnel.Option{tunnel.WithRequestTimeout(100 * time.Millisecond), tunnel.WithConfirm(true, 300*time.Millisecond), tunnel.WithConnectTimeout(time.Second)}

	t.Run("ack on another channel", func(t *testing.T) {
		leak.Check(t)
		p := acceptOn7(t, func(p *fakeknx.Peer, d fakeknx.Datagram) {
			if m, ok := d.Msg.(*knxnetip.TunnellingRequest); ok {
				p.Send(d.From, &knxnetip.TunnellingAck{Channel: m.Channel + 1, Seq: m.Seq})
				p.Send(d.From, &knxnetip.TunnellingAck{Channel: m.Channel, Seq: m.Seq + 1})
			}
		})
		c, err := tunnel.Dial(ctx(t), p.String(), opts...)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		start := time.Now()
		err = c.Send(short, ld)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 500*time.Millisecond {
			t.Fatalf("send with a 50 ms context: %v after %v", err, time.Since(start))
		}
		if err := c.Send(ctx(t), ld); !errors.Is(err, knx.ErrConnectionLost) {
			t.Fatalf("send without a valid ACK: %v", err)
		}
	})

	t.Run("no confirmation", func(t *testing.T) {
		leak.Check(t)
		p := acceptOn7(t, func(p *fakeknx.Peer, d fakeknx.Datagram) {
			if m, ok := d.Msg.(*knxnetip.TunnellingRequest); ok {
				p.Send(d.From, &knxnetip.TunnellingAck{Channel: m.Channel, Seq: m.Seq})
				// An L_Data.con of another telegram.
				other := cemi.NewGroupFrame(cemi.LDataCon, 0, knx.MustParseGroupAddress("1/2/4"), knx.PriorityLow, []byte{0x00, 0x81})
				b, _ := cemi.Marshal(other)
				p.Send(d.From, &knxnetip.TunnellingRequest{Channel: 7, Seq: m.Seq, CEMI: b})
			}
		})
		c, err := tunnel.Dial(ctx(t), p.String(), opts...)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := c.Send(ctx(t), ld); !errors.Is(err, knx.ErrNotConfirmed) {
			t.Fatalf("send without its L_Data.con: %v", err)
		}
	})

	t.Run("request flood", func(t *testing.T) {
		leak.Check(t)
		var stop atomic.Bool
		var wg sync.WaitGroup
		t.Cleanup(func() { stop.Store(true); wg.Wait() })
		var started atomic.Bool
		ind, _ := cemi.Marshal(cemi.NewGroupFrame(cemi.LDataInd, 0x1101, knx.MustParseGroupAddress("1/2/3"), knx.PriorityLow, []byte{0x00, 0x81}))
		p := acceptOn7(t, func(p *fakeknx.Peer, d fakeknx.Datagram) {
			// The client's requests are never acknowledged; its first one
			// starts the flood of server requests.
			if _, ok := d.Msg.(*knxnetip.TunnellingRequest); ok && started.CompareAndSwap(false, true) {
				to := d.From
				wg.Go(func() {
					for i := 0; i < 3000 && !stop.Load(); i++ {
						ch := uint8(7)
						if i%10 == 9 {
							ch = 8
						}
						p.Send(to, &knxnetip.TunnellingRequest{Channel: ch, Seq: uint8(i), CEMI: ind})
					}
				})
			}
		})
		c, err := tunnel.Dial(ctx(t), p.String(), append(opts, tunnel.WithQueueSize(8))...)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := c.Send(ctx(t), ld); !errors.Is(err, knx.ErrConnectionLost) {
			t.Fatalf("send to a server that never acknowledges: %v", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("send took %v", d)
		}
		done := make(chan struct{})
		go func() { c.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Close hangs during a request flood")
		}
	})
}

// TestHostileDiscovery: description and search against a peer that
// answers with garbage and truncated responses end with an error or no
// result within their deadlines.
func TestHostileDiscovery(t *testing.T) {
	leak.Check(t)
	resp, _ := knxnetip.Marshal(&knxnetip.SearchResponse{Control: knxnetip.NewHPAI(netip.MustParseAddrPort("127.0.0.1:3671"))})
	desc, _ := knxnetip.Marshal(&knxnetip.DescriptionResponse{})
	p := hostilePeer(t, func(p *fakeknx.Peer, d fakeknx.Datagram) {
		for _, b := range noise(uint64(len(d.Raw)), 10) {
			p.SendRaw(d.From, b)
		}
		p.SendRaw(d.From, resp[:len(resp)-2])
		p.SendRaw(d.From, desc)
		p.SendRaw(d.From, desc[:6])
	})
	c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	// The empty DESCRIPTION_RESPONSE is a valid frame: Describe may return
	// it (without DIBs); it must not return later than its timeout.
	_, _ = discovery.Describe(c, p.String(), discovery.WithTimeout(300*time.Millisecond))
	rs, err := discovery.Search(c, discovery.WithUnicast(p.String()), discovery.WithTimeout(300*time.Millisecond))
	if err != nil && !errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("search: %v", err)
	}
	for _, r := range rs {
		if _, ok := r.DIBs.DeviceInfo(); !ok {
			t.Errorf("a result without DEVICE_INFO: %+v", r)
		}
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("discovery took %v", d)
	}
}

// TestHostileReconnectSameEndpoint: a client that lost its connection
// (heartbeat failed, no DISCONNECT exchanged) connects again from the same
// endpoint, as tunnel.WithReconnect does, and starts its sequence counters
// at 0. Its new connection must start at 0 on the server too: otherwise
// the server acknowledges the client's first request as a repetition and
// drops it, and sends its own first request with a number the client
// does not expect.
func TestHostileReconnectSameEndpoint(t *testing.T) {
	leak.Check(t)
	s, addr := startServer(t)
	var mu sync.Mutex
	got := map[byte]int{}
	cancel := s.Subscribe(func(tg server.Telegram) {
		if tg.Origin == server.FromTunnel && len(tg.Frame.TPDU) == 3 {
			mu.Lock()
			got[tg.Frame.TPDU[2]]++
			mu.Unlock()
		}
	})
	defer cancel()
	count := func(v byte) int { mu.Lock(); defer mu.Unlock(); return got[v] }
	r := dialRawTunnel(t, addr)
	first := r.ch
	if !r.request(t, r.ch, 0, groupWriteCEMI(t, 1), 5) {
		t.Fatal("sequence 0 not acknowledged")
	}
	eventually(t, 2*time.Second, "delivery of the first write", func() bool { return count(1) == 1 })
	// Drain the L_Data.con (server sequence 0).
	select {
	case <-r.reqs:
	case <-time.After(2 * time.Second):
		t.Fatal("no L_Data.con")
	}

	// Connect again from the same endpoint.
	r.p.Send(r.srv, &knxnetip.ConnectRequest{Control: r.p.HPAI(), Data: r.p.HPAI(), CRI: knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)})
	resp, _ := fakeknx.Expect[*knxnetip.ConnectResponse](r.p, 2*time.Second)
	if resp.Status != knxnetip.StatusNoError {
		t.Fatalf("reconnect: %s", resp.Status)
	}
	r.ch = resp.Channel
	if !r.request(t, r.ch, 0, groupWriteCEMI(t, 2), 5) {
		t.Fatal("the first request of the new connection was not acknowledged")
	}
	var con *knxnetip.TunnellingRequest
	select {
	case con = <-r.reqs:
	case <-time.After(500 * time.Millisecond):
	}
	if resp.Channel != first {
		t.Errorf("reconnect from the same endpoint: channel %d, want the old channel %d", resp.Channel, first)
	}
	if count(2) != 1 {
		t.Fatalf("the first write of the new connection delivered %d times", count(2))
	}
	if con == nil || con.Seq != 0 {
		t.Fatalf("the server's first request on the new connection has sequence %v, want 0", seqOf(con))
	}
}

func seqOf(r *knxnetip.TunnellingRequest) any {
	if r == nil {
		return "none"
	}
	return r.Seq
}
