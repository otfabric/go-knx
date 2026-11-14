// SPDX-License-Identifier: MIT

package server_test

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// The keys are derived once: the derivation is slow under -race and
// coverage, and the tests with short authentication timeouts must not
// spend that time while a session waits.
var (
	cred2Dev = sync.OnceValue(func() secure.Credentials {
		c, _ := secure.NewCredentials(2, "pw2", "dev")
		return c
	})
	passwordKeys = sync.OnceValue(func() map[string]secure.Key {
		m := map[string]secure.Key{}
		for _, pw := range []string{"pw1", "pw2"} {
			m[pw], _ = secure.UserPasswordKey(pw)
		}
		return m
	})
)

// warmKeys derives the keys before a test opens sessions.
func warmKeys() { _, _ = cred2Dev(), passwordKeys() }

// secureDial opens and closes a secure tunnel of user 2.
func secureDial(t *testing.T, s *server.Server, udp bool) error {
	t.Helper()
	cred := cred2Dev()
	opts := []tunnel.Option{tunnel.WithSecure(cred), tunnel.WithConnectTimeout(time.Second)}
	if udp {
		opts = append(opts, tunnel.WithUDP())
	} else {
		opts = append(opts, tunnel.WithTCP())
	}
	c, err := tunnel.Dial(ctx(t), addrOf(s).String(), opts...)
	if err == nil {
		_ = c.Close()
	}
	return err
}

// udpSession is a hand-driven secure session over UDP.
type udpSession struct {
	t    *testing.T
	p    *fakeknx.Peer
	srv  netip.AddrPort
	sess *secure.Session
	kp   *secure.KeyPair
	resp *knxnetip.SessionResponse
}

func openUDPSession(t *testing.T, s *server.Server) *udpSession {
	t.Helper()
	p := fakeknx.Listen(t)
	kp, _ := secure.NewKeyPair()
	p.Send(addrOf(s), &knxnetip.SessionRequest{Control: p.HPAI(), PublicKey: kp.Public})
	resp, _ := fakeknx.Expect[*knxnetip.SessionResponse](p, wait)
	key, _ := kp.SessionKey(resp.PublicKey)
	return &udpSession{t: t, p: p, srv: addrOf(s), sess: secure.NewSession(resp.SessionID, key, [6]byte{}), kp: kp, resp: resp}
}

func (u *udpSession) send(m knxnetip.Message) {
	u.t.Helper()
	b, err := u.sess.Marshal(m)
	if err != nil {
		u.t.Fatal(err)
	}
	u.p.SendRaw(u.srv, b)
}

// next returns the next frame of the session.
func (u *udpSession) next() knxnetip.Message {
	u.t.Helper()
	w, _ := fakeknx.Expect[*knxnetip.SecureWrapper](u.p, wait)
	frame, err := u.sess.Unwrap(w)
	if err != nil {
		u.t.Fatal(err)
	}
	m, err := knxnetip.Parse(frame)
	if err != nil {
		u.t.Fatal(err)
	}
	return m
}

func authenticateMsg(user uint8, password string, client, server [32]byte) *knxnetip.SessionAuthenticate {
	k, ok := passwordKeys()[password]
	if !ok {
		k, _ = secure.UserPasswordKey(password)
	}
	return &knxnetip.SessionAuthenticate{UserID: user, MAC: secure.AuthenticateMAC(k, user, client, server)}
}

func (u *udpSession) authenticate(user uint8, password string) {
	u.t.Helper()
	u.send(authenticateMsg(user, password, u.kp.Public, u.resp.PublicKey))
	if st, ok := u.next().(*knxnetip.SessionStatus); !ok || st.Status != knxnetip.SessionAuthSuccess {
		u.t.Fatalf("authenticate: %v", st)
	}
}

// TestSecureSessionUDPSpoofedRequests: SESSION_REQUESTs whose control
// endpoint is elsewhere fill the sessions; a user still opens a session,
// in place of the oldest that has not authenticated.
func TestSecureSessionUDPSpoofedRequests(t *testing.T) {
	warmKeys()
	s, m := start(t, secureOptions())
	p := fakeknx.Listen(t)
	sink := fakeknx.Listen(t)
	for range 6 { // tunnels + 4
		kp, _ := secure.NewKeyPair()
		p.Send(addrOf(s), &knxnetip.SessionRequest{Control: sink.HPAI(), PublicKey: kp.Public})
	}
	eventually(t, "the session responses", func() bool {
		return m.get(func(m *metrics) int { return m.sent[uint16(knxnetip.SessionResponseType)] }) >= 6
	})
	if err := secureDial(t, s, true); err != nil {
		t.Fatalf("secure dial with the sessions taken: %v", err)
	}
	if n := m.get(func(m *metrics) int { return m.dropped["session_replaced"] }); n < 1 {
		t.Errorf("session_replaced = %d", n)
	}
}

// TestSecureSessionUDPUnauthenticatedKeepAlive: keep-alives do not keep a
// session that has not authenticated: it ends at the authentication
// timeout, and a user opens a session meanwhile.
func TestSecureSessionUDPUnauthenticatedKeepAlive(t *testing.T) {
	warmKeys()
	s, m := start(t, secureOptions(), server.WithSecureAuthTimeout(400*time.Millisecond))
	var held []*udpSession
	for range 6 {
		held = append(held, openUDPSession(t, s))
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			for _, u := range held {
				if b, err := u.sess.Marshal(&knxnetip.SessionStatus{Status: knxnetip.SessionKeepAlive}); err == nil {
					u.p.SendRaw(u.srv, b)
				}
			}
		}
	}()
	if err := secureDial(t, s, true); err != nil {
		t.Errorf("secure dial with the sessions held: %v", err)
	}
	time.Sleep(800 * time.Millisecond) // past the authentication timeout
	close(stop)
	<-done
	before := m.get(func(m *metrics) int { return m.dropped["session"] })
	held[5].send(&knxnetip.ConnectionStateRequest{Channel: 1, Control: held[5].p.HPAI()})
	eventually(t, "the session to be gone", func() bool { return m.get(func(m *metrics) int { return m.dropped["session"] }) > before })
}

// TestSecureSessionUDPAuthenticatedKept: authenticated sessions are not
// replaced; with all of them authenticated a new session is refused, and
// they stay open past the authentication timeout.
func TestSecureSessionUDPAuthenticatedKept(t *testing.T) {
	warmKeys()
	s, _ := start(t, secureOptions(), server.WithSecureAuthTimeout(200*time.Millisecond))
	var held []*udpSession
	for range 6 {
		u := openUDPSession(t, s)
		u.authenticate(2, "pw2")
		held = append(held, u)
	}
	p := fakeknx.Listen(t)
	kp, _ := secure.NewKeyPair()
	p.Send(addrOf(s), &knxnetip.SessionRequest{Control: p.HPAI(), PublicKey: kp.Public})
	fakeknx.ExpectNone[*knxnetip.SessionResponse](p, 300*time.Millisecond)
	// Past the authentication timeout the sessions answer.
	held[0].send(&knxnetip.ConnectionStateRequest{Channel: 9, Control: held[0].p.HPAI()})
	if r, ok := held[0].next().(*knxnetip.ConnectionStateResponse); !ok || r.Status != knxnetip.StatusConnectionID {
		t.Fatalf("answer of an authenticated session: %v", r)
	}
}

// TestSecureSessionUDPDisconnectInSession: the server's DISCONNECT_REQUEST
// for a connection of a secure session over UDP is sent in the session.
func TestSecureSessionUDPDisconnectInSession(t *testing.T) {
	s, _ := start(t, secureOptions())
	u := openUDPSession(t, s)
	u.authenticate(2, "pw2")
	u.send(&knxnetip.ConnectRequest{Control: u.p.HPAI(), Data: u.p.HPAI(), CRI: knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)})
	if r, ok := u.next().(*knxnetip.ConnectResponse); !ok || r.Status != knxnetip.StatusNoError {
		t.Fatalf("connect: %v", r)
	}
	go s.Close()
	if d, ok := u.next().(*knxnetip.DisconnectRequest); !ok {
		t.Fatalf("got %v, want a DISCONNECT_REQUEST in the session", d)
	}
}

// tcpRaw is a hand-driven TCP connection.
type tcpRaw struct {
	t *testing.T
	c net.Conn
}

func dialTCPRaw(t *testing.T, s *server.Server) *tcpRaw {
	t.Helper()
	c, err := net.Dial("tcp4", addrOf(s).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &tcpRaw{t: t, c: c}
}

func (r *tcpRaw) send(b []byte) error {
	_ = r.c.SetWriteDeadline(time.Now().Add(wait))
	_, err := r.c.Write(b)
	return err
}

func (r *tcpRaw) sendMsg(m knxnetip.Message) {
	r.t.Helper()
	b, err := knxnetip.Marshal(m)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.send(b); err != nil {
		r.t.Fatal(err)
	}
}

func (r *tcpRaw) next() (knxnetip.Message, error) {
	_ = r.c.SetReadDeadline(time.Now().Add(wait))
	b, err := knxnetip.ReadFrame(r.c)
	if err != nil {
		return nil, err
	}
	return knxnetip.Parse(b)
}

// describe sends a DESCRIPTION_REQUEST and waits for the answer: the
// connection is accepted.
func (r *tcpRaw) describe() {
	r.t.Helper()
	r.sendMsg(&knxnetip.DescriptionRequest{Control: knxnetip.TCPHPAI()})
	if m, err := r.next(); err != nil {
		r.t.Fatal(err)
	} else if _, ok := m.(*knxnetip.DescriptionResponse); !ok {
		r.t.Fatalf("got %v", m)
	}
}

// TestSecureTCPUnauthenticated: TCP connections that send plain frames
// but never authenticate hold no slot from a user, and end at the
// authentication timeout although they keep sending.
func TestSecureTCPUnauthenticated(t *testing.T) {
	warmKeys()
	s, m := start(t, secureOptions(), server.WithSecureAuthTimeout(500*time.Millisecond))
	search, _ := knxnetip.Marshal(&knxnetip.SearchRequest{Discovery: knxnetip.RouteBackHPAI()})
	var conns []*tcpRaw
	for range 6 {
		r := dialTCPRaw(t, s)
		r.describe()
		conns = append(conns, r)
	}
	opened := time.Now()
	if err := secureDial(t, s, false); err != nil {
		t.Fatalf("secure TCP dial with the connections taken: %v", err)
	}
	if n := m.get(func(m *metrics) int { return m.dropped["session_replaced"] }); n < 1 {
		t.Errorf("session_replaced = %d", n)
	}
	// The last one keeps sending; it still ends at the deadline.
	last := conns[5]
	for time.Since(opened) < 2*time.Second {
		if err := last.send(search); err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = last.c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 64)
	for {
		if _, err := last.c.Read(buf); err != nil {
			if errors.Is(err, net.ErrClosed) || isTimeout(err) {
				t.Fatalf("connection not closed by the server: %v", err)
			}
			break
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TestSecureTCPAuthenticatedKept: authenticated TCP sessions are not
// replaced; a further connection is refused.
func TestSecureTCPAuthenticatedKept(t *testing.T) {
	warmKeys()
	s, _ := start(t, secureOptions(), server.WithSecureAuthTimeout(300*time.Millisecond))
	for range 6 {
		r := dialTCPRaw(t, s)
		kp, _ := secure.NewKeyPair()
		r.sendMsg(&knxnetip.SessionRequest{Control: knxnetip.TCPHPAI(), PublicKey: kp.Public})
		m, err := r.next()
		if err != nil {
			t.Fatal(err)
		}
		resp := m.(*knxnetip.SessionResponse)
		key, _ := kp.SessionKey(resp.PublicKey)
		sess := secure.NewSession(resp.SessionID, key, [6]byte{})
		b, _ := sess.Marshal(authenticateMsg(1, "pw1", kp.Public, resp.PublicKey))
		if err := r.send(b); err != nil {
			t.Fatal(err)
		}
		m, err = r.next()
		if err != nil {
			t.Fatal(err)
		}
		frame, err := sess.Unwrap(m.(*knxnetip.SecureWrapper))
		if err != nil {
			t.Fatal(err)
		}
		if st, _ := knxnetip.Parse(frame); st.(*knxnetip.SessionStatus).Status != knxnetip.SessionAuthSuccess {
			t.Fatalf("authenticate: %v", st)
		}
	}
	extra := dialTCPRaw(t, s)
	if _, err := extra.next(); err == nil || isTimeout(err) {
		t.Fatalf("extra connection: %v, want closed", err)
	}
}

// TestSecureTunnelSourceBound: a secure tunnel sends with its own address;
// a telegram with another source is dropped.
func TestSecureTunnelSourceBound(t *testing.T) {
	s, m := start(t, secureOptions())
	cred1, _ := secure.NewCredentials(1, "pw1", "dev")
	cred2, _ := secure.NewCredentials(2, "pw2", "dev")
	other := dialTunnel(t, s, tunnel.WithSecure(cred1))
	c := dialTunnel(t, s, tunnel.WithSecure(cred2))
	send := func(src knx.IndividualAddress, v byte) error {
		t.Helper()
		f := write(ga, v)
		f.Source = src
		return c.Send(ctx(t), f)
	}
	if err := send(other.IndividualAddress(), 1); err == nil {
		t.Error("foreign source confirmed")
	}
	eventually(t, "the drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["source_address"] }) == 1 })
	noFrame(t, other)
	if err := send(slot2, 2); err != nil {
		t.Fatal(err)
	}
	if f := receive(t, other); lastOctet(f) != 2 || f.Source != slot2 {
		t.Fatalf("own address: %v", f)
	}
	if err := send(0, 3); err != nil {
		t.Fatal(err)
	}
	if f := receive(t, other); lastOctet(f) != 3 || f.Source != slot2 {
		t.Fatalf("source 0: %v", f)
	}
}

// TestChannelsExhausted: with 255 tunnelling addresses all 255 channels
// can be taken; a device management connection is then refused and no
// connection is replaced.
func TestChannelsExhausted(t *testing.T) {
	s, _ := start(t, server.WithTunnelAddresses(addrs(255)...))
	p := fakeknx.Listen(t)
	connect := func(i int, cri knxnetip.CRI) *knxnetip.ConnectResponse {
		t.Helper()
		data := knxnetip.NewHPAI(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(20000+i)))
		p.Send(addrOf(s), &knxnetip.ConnectRequest{Control: p.HPAI(), Data: data, CRI: cri})
		r, _ := fakeknx.Expect[*knxnetip.ConnectResponse](p, wait)
		return r
	}
	for i := range 255 {
		if r := connect(i, knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)); r.Status != knxnetip.StatusNoError {
			t.Fatalf("tunnel %d: %s", i, r.Status)
		}
	}
	before := s.Connections()
	g := runtime.NumGoroutine()
	for i := range 3 {
		if r := connect(300+i, knxnetip.CRI{Type: knxnetip.DeviceManagementConnection}); r.Status != knxnetip.StatusNoMoreConnections {
			t.Fatalf("device management %d: %s", i, r.Status)
		}
	}
	after := s.Connections()
	if len(after) != 255 || !sameConnections(before, after) {
		t.Fatalf("connections changed: %d -> %d", len(before), len(after))
	}
	if n := runtime.NumGoroutine(); n > g {
		t.Errorf("goroutines %d -> %d", g, n)
	}
}

func sameConnections(a, b []server.Connection) bool {
	key := func(cs []server.Connection) map[uint8]string {
		m := map[uint8]string{}
		for _, c := range cs {
			m[c.Channel] = fmt.Sprint(c.Address, c.Data)
		}
		return m
	}
	return reflect.DeepEqual(key(a), key(b))
}

// TestSearchExtRepeatedDIBs: a DIB type requested repeatedly is answered
// once.
func TestSearchExtRepeatedDIBs(t *testing.T) {
	s, _ := start(t)
	p := fakeknx.Listen(t)
	ask := func(types []byte) *knxnetip.SearchResponse {
		t.Helper()
		p.Send(addrOf(s), &knxnetip.SearchRequestExt{Discovery: p.HPAI(), Params: []knxnetip.SearchParam{
			{Type: knxnetip.SRPRequestDIBs, Data: types}}})
		r, _ := fakeknx.Expect[*knxnetip.SearchResponse](p, wait)
		return r
	}
	repeated := make([]byte, 200)
	for i := range repeated {
		repeated[i] = byte(knxnetip.DIBTunnellingInfo)
	}
	many := ask(repeated)
	n := 0
	for _, d := range many.DIBs {
		if d.Type() == knxnetip.DIBTunnellingInfo {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d TUNNELLING_INFO DIBs", n)
	}
	if one := ask([]byte{byte(knxnetip.DIBTunnellingInfo)}); !reflect.DeepEqual(one.DIBs, many.DIBs) {
		t.Fatalf("repeated: %v\nsingle: %v", many.DIBs, one.DIBs)
	}
}

// TestSearchExtManyTunnels: with 255 tunnelling addresses the KNX_ADDRESSES
// and TUNNELLING_INFO DIBs list the entries that fit in a DIB.
func TestSearchExtManyTunnels(t *testing.T) {
	s, _ := start(t, server.WithTunnelAddresses(addrs(255)...))
	p := fakeknx.Listen(t)
	p.Send(addrOf(s), &knxnetip.SearchRequestExt{Discovery: p.HPAI(), Params: []knxnetip.SearchParam{
		{Type: knxnetip.SRPRequestDIBs, Data: []byte{byte(knxnetip.DIBKNXAddresses), byte(knxnetip.DIBTunnellingInfo)}}}})
	r, _ := fakeknx.Expect[*knxnetip.SearchResponse](p, wait)
	var got int
	for _, d := range r.DIBs {
		switch d := d.(type) {
		case knxnetip.KNXAddresses:
			got++
			if len(d.Addresses) != 126 || d.Addresses[0] != serverAddr {
				t.Errorf("KNX_ADDRESSES: %d addresses", len(d.Addresses))
			}
		case knxnetip.TunnellingInfo:
			got++
			if len(d.Slots) != 62 {
				t.Errorf("TUNNELLING_INFO: %d slots", len(d.Slots))
			}
		}
	}
	if got != 2 {
		t.Fatalf("DIBs %v", r.DIBs)
	}
}

// TestSecureAuthTimeoutOption rejects a non-positive timeout.
func TestSecureAuthTimeoutOption(t *testing.T) {
	if _, err := server.New(server.WithSecureAuthTimeout(0)); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("err = %v", err)
	}
}

// TestTCPLimitPlain: a plain server refuses a TCP connection beyond the
// limit and keeps the others.
func TestTCPLimitPlain(t *testing.T) {
	s, _ := start(t)
	var conns []*tcpRaw
	for range 6 {
		r := dialTCPRaw(t, s)
		r.describe()
		conns = append(conns, r)
	}
	extra := dialTCPRaw(t, s)
	if _, err := extra.next(); err == nil || isTimeout(err) {
		t.Fatalf("extra connection: %v, want closed", err)
	}
	conns[0].describe()
}
