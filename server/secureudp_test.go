// SPDX-License-Identifier: MIT

package server_test

import (
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

func secureOptions() server.Option {
	dev, _ := secure.DeviceAuthenticationCode("dev")
	u1, _ := secure.UserPasswordKey("pw1")
	u2, _ := secure.UserPasswordKey("pw2")
	return server.WithSecure(dev, map[uint8]server.SecureUser{1: {Key: u1}, 2: {Key: u2, Address: slot2}})
}

func groupWrite(t *testing.T, c *tunnel.Conn, v byte) {
	t.Helper()
	tpdu, _ := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{v}})
	if err := c.Send(ctx(t), cemi.NewGroupFrame(cemi.LDataReq, 0, ga, knx.PriorityLow, tpdu)); err != nil {
		t.Fatal(err)
	}
}

// TestSecureSessionUDP: secure tunnelling over UDP, next to a secure
// session over TCP.
func TestSecureSessionUDP(t *testing.T) {
	s, m := start(t, secureOptions())
	cred2, _ := secure.NewCredentials(2, "pw2", "dev")
	cred1, _ := secure.NewCredentials(1, "pw1", "dev")
	u := dialTunnel(t, s, tunnel.WithSecure(cred2), tunnel.WithUDP(), tunnel.WithHeartbeat(100*time.Millisecond, time.Second, 1))
	if u.TCP() || u.IndividualAddress() != slot2 {
		t.Fatalf("UDP session: tcp %v, address %s", u.TCP(), u.IndividualAddress())
	}
	tc := dialTunnel(t, s, tunnel.WithSecure(cred1))
	groupWrite(t, u, 7)
	if f := receive(t, tc); lastOctet(f) != 7 {
		t.Fatalf("TCP client got %v", f)
	}
	groupWrite(t, tc, 8)
	if f := receive(t, u); lastOctet(f) != 8 {
		t.Fatalf("UDP client got %v", f)
	}
	time.Sleep(400 * time.Millisecond) // heartbeats in the session
	if u.State() != knx.StateConnected {
		t.Errorf("state after heartbeats: %v", u.State())
	}

	bad, _ := secure.NewCredentials(2, "wrong", "")
	if _, err := tunnel.Dial(ctx(t), addrOf(s).String(), tunnel.WithSecure(bad), tunnel.WithUDP()); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("wrong password over UDP: %v", err)
	}
	if _, err := tunnel.Dial(ctx(t), addrOf(s).String()); !errors.Is(err, knx.ErrRejected) {
		t.Errorf("plain UDP tunnel: %v", err)
	}

	// Raw frames: a wrapper of an unknown session, an invalid key.
	p := fakeknx.Listen(t)
	w, _ := secure.Seal(secure.Key{}, 999, 0, [6]byte{}, 0, []byte{6, 0x10, 2, 9, 0, 6})
	p.Send(addrOf(s), w)
	eventually(t, "session drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["session"] }) >= 1 })
	p.Send(addrOf(s), &knxnetip.SessionRequest{Control: p.HPAI()})
	if x, ok := p.Next(300 * time.Millisecond); ok {
		t.Errorf("answer to an invalid public key: %v", x.Msg)
	}
	// A session whose user never authenticates.
	kp, _ := secure.NewKeyPair()
	p.Send(addrOf(s), &knxnetip.SessionRequest{Control: p.HPAI(), PublicKey: kp.Public})
	resp, _ := fakeknx.Expect[*knxnetip.SessionResponse](p, wait)
	key, _ := kp.SessionKey(resp.PublicKey)
	sess := secure.NewSession(resp.SessionID, key, [6]byte{})
	b, _ := sess.Marshal(&knxnetip.ConnectionStateRequest{Channel: 1, Control: p.HPAI()})
	p.SendRaw(addrOf(s), b)
	got, _ := fakeknx.Expect[*knxnetip.SecureWrapper](p, wait)
	frame, err := sess.Unwrap(got)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := knxnetip.Parse(frame); st.(*knxnetip.SessionStatus).Status != knxnetip.SessionUnauthenticated {
		t.Errorf("unauthenticated request: %v", st)
	}
	bad2, _ := sess.Wrap([]byte{6, 0x10, 2, 5, 0, 6})
	p.Send(addrOf(s), bad2)
	tampered, _ := sess.Wrap([]byte{6, 0x10, 2, 9, 0, 6})
	tampered.MAC[0] ^= 1
	p.Send(addrOf(s), tampered)
	eventually(t, "decode errors", func() bool { return m.get(func(m *metrics) int { return m.decode }) >= 2 })
	// Closing the session.
	cl, _ := sess.Marshal(&knxnetip.SessionStatus{Status: knxnetip.SessionClose})
	p.SendRaw(addrOf(s), cl)
	time.Sleep(100 * time.Millisecond)
	p.SendRaw(addrOf(s), b)
	eventually(t, "closed session", func() bool { return m.get(func(m *metrics) int { return m.dropped["session"] }) >= 2 })
}

// TestSecureSessionUDPExpiry: an idle UDP session ends with its tunnel.
func TestSecureSessionUDPExpiry(t *testing.T) {
	s, _ := start(t, secureOptions(), server.WithConnectionAliveTime(300*time.Millisecond))
	cred, _ := secure.NewCredentials(2, "pw2", "")
	c, err := tunnel.Dial(ctx(t), addrOf(s).String(), tunnel.WithSecure(cred), tunnel.WithUDP(),
		tunnel.WithHeartbeat(time.Hour, time.Second, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	eventually(t, "the connection to end", func() bool { return len(s.Connections()) == 0 })
}

// TestSecureSessionUDPNoServer: a SESSION_REQUEST nobody answers.
func TestSecureSessionUDPNoServer(t *testing.T) {
	p := fakeknx.Listen(t)
	cred, _ := secure.NewCredentials(2, "pw2", "")
	if _, err := tunnel.Dial(ctx(t), p.Addr().String(), tunnel.WithSecure(cred), tunnel.WithUDP(), tunnel.WithConnectTimeout(300*time.Millisecond)); !errors.Is(err, knx.ErrTimeout) {
		t.Errorf("no answer: %v", err)
	}
	if _, err := tunnel.Dial(ctx(t), p.Addr().String(), tunnel.WithTCP(), tunnel.WithUDP()); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("TCP and UDP: %v", err)
	}
}

// TestSecureRouting: the server's routing with a backbone key.
func TestSecureRouting(t *testing.T) {
	key := secure.Key{1, 2, 3}
	s, m, _, local := startRouter(t, server.WithSecureRouting(key, 100*time.Millisecond))
	c := dialTunnel(t, s)
	time.Sleep(600 * time.Millisecond) // the timer synchronisation
	p := fakeknx.Listen(t)
	plain, _ := knxnetip.Marshal(&knxnetip.RoutingIndication{CEMI: indication(5, 6)})
	w, _ := secure.Seal(key, 0, 1<<40, [6]byte{0, 0xfa, 1}, 1, plain)
	p.Send(local, w)
	if f := receive(t, c); lastOctet(f) != 5 {
		t.Fatalf("secured indication: %v", f)
	}
	p.Send(local, &knxnetip.RoutingIndication{CEMI: indication(6, 6)})
	eventually(t, "plain drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["unsecured"] }) == 1 })
	old, _ := secure.Seal(key, 0, 5, [6]byte{}, 1, plain)
	p.Send(local, old)
	eventually(t, "timer drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["timer"] }) == 1 })
	other, _ := secure.Seal(secure.Key{9}, 0, 1<<41, [6]byte{}, 1, plain)
	p.Send(local, other)
	inner, _ := secure.Seal(key, 0, 1<<41, [6]byte{}, 1, []byte{6, 0x10, 5, 0x30, 0, 0x50})
	p.Send(local, inner)
	eventually(t, "decode errors", func() bool { return m.get(func(m *metrics) int { return m.decode }) >= 2 })
	unexpected, _ := secure.Seal(key, 0, 1<<41+1, [6]byte{}, 1, []byte{6, 0x10, 9, 0x54, 0, 8, 4, 0})
	p.Send(local, unexpected)
	eventually(t, "unexpected drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["unexpected"] }) == 1 })
	p.Send(local, secure.NewTimerNotify(secure.Key{9}, 1, [6]byte{}, 1))
	eventually(t, "notify drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["authentication"] }) == 1 })
	p.Send(local, secure.NewTimerNotify(key, 1<<42, [6]byte{}, 1))

	// Outbound: the tunnel's telegram goes to the group in a wrapper.
	groupWrite(t, c, 9)
	eventually(t, "secured indication sent", func() bool {
		return m.get(func(m *metrics) int { return m.sent[uint16(knxnetip.SecureWrapperType)] }) >= 1
	})
	if n := m.get(func(m *metrics) int { return m.sent[uint16(knxnetip.RoutingIndicationType)] }); n != 0 {
		t.Errorf("%d plain indications sent", n)
	}
	// Session wrappers to a server without secure sessions are dropped.
	sw, _ := secure.Seal(key, 3, 1, [6]byte{}, 1, plain)
	p.Send(local, sw)
	p.Send(local, &knxnetip.SessionRequest{Control: p.HPAI()})
	eventually(t, "no security", func() bool { return m.get(func(m *metrics) int { return m.dropped["no_security"] }) >= 1 })
	if _, err := server.New(server.WithSecureRouting(key, 0)); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("secure routing without routing: %v", err)
	}
	if _, err := server.New(server.WithRouting(true), server.WithSecureRouting(key, -1)); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("negative latency: %v", err)
	}
}
