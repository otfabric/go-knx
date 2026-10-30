// SPDX-License-Identifier: MIT

package tunnel

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
)

// scripted is one side of a secure session written by hand: the server
// of the handshake tests.
type scripted struct {
	t    *testing.T
	c    net.Conn
	sess *secure.Session
	kp   *secure.KeyPair
	req  *knxnetip.SessionRequest
}

func (s *scripted) read() knxnetip.Message {
	s.t.Helper()
	b, err := knxnetip.ReadFrame(s.c)
	if err != nil {
		s.t.Errorf("server read: %v", err)
		return nil
	}
	m, err := knxnetip.Parse(b)
	if err != nil {
		s.t.Errorf("server parse: %v", err)
	}
	return m
}

func (s *scripted) write(m knxnetip.Message) {
	b, _ := knxnetip.Marshal(m)
	_, _ = s.c.Write(b)
}

func (s *scripted) writeWrapped(m knxnetip.Message) {
	b, _ := s.sess.Marshal(m)
	_, _ = s.c.Write(b)
}

// respond answers the SESSION_REQUEST with a valid SESSION_RESPONSE.
func (s *scripted) respond(device secure.Key) {
	s.req, _ = s.read().(*knxnetip.SessionRequest)
	s.kp, _ = secure.NewKeyPair()
	key, _ := s.kp.SessionKey(s.req.PublicKey)
	s.sess = secure.NewSession(5, key, [6]byte{1})
	s.write(&knxnetip.SessionResponse{SessionID: 5, PublicKey: s.kp.Public, MAC: secure.ResponseMAC(device, 5, s.req.PublicKey, s.kp.Public)})
}

func secureDial(t *testing.T, cred secure.Credentials, script func(s *scripted)) (*secureTransport, error) {
	t.Helper()
	st, done, err := secureDialAsync(t, cred, script)
	<-done
	return st, err
}

// secureDialAsync returns before the script ends.
func secureDialAsync(t *testing.T, cred secure.Credentials, script func(s *scripted)) (*secureTransport, <-chan struct{}, error) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		script(&scripted{t: t, c: c})
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := netip.MustParseAddrPort(ln.Addr().String())
	st, err := handshake(&tcpTransport{c: c, server: srv}, srv, knxnetip.TCPHPAI(), cred, 2*time.Second)
	if err != nil {
		_ = c.Close()
	}
	return st, done, err
}

func TestHandshakeErrors(t *testing.T) {
	dev, _ := secure.DeviceAuthenticationCode("dev")
	cred, _ := secure.NewCredentials(2, "pw", "dev")
	for name, tc := range map[string]struct {
		script func(s *scripted)
		want   error
	}{
		"refused": {func(s *scripted) { s.read(); s.write(&knxnetip.SessionStatus{Status: knxnetip.SessionAuthFailed}) }, knx.ErrRejected},
		"other":   {func(s *scripted) { s.read(); s.write(&knxnetip.ConnectResponse{Status: 0x22}) }, knx.ErrSecurity},
		"closed":  {func(s *scripted) { s.read() }, knx.ErrConnectionLost},
		"key": {func(s *scripted) {
			s.read()
			s.write(&knxnetip.SessionResponse{SessionID: 1})
		}, knx.ErrSecurity},
		"device": {func(s *scripted) { s.respond(secure.Key{9}) }, knx.ErrSecurity},
		"plain status": {func(s *scripted) {
			s.respond(dev)
			s.read()
			s.write(&knxnetip.SessionStatus{Status: knxnetip.SessionAuthSuccess})
		}, knx.ErrSecurity},
		"auth failed": {func(s *scripted) {
			s.respond(dev)
			s.read()
			s.writeWrapped(&knxnetip.SessionStatus{Status: knxnetip.SessionAuthFailed})
		}, knx.ErrSecurity},
		"malformed": {func(s *scripted) {
			s.respond(dev)
			s.read()
			w, _ := s.sess.Wrap([]byte{6, 0x10, 9, 0x54, 0, 0x20})
			b, _ := knxnetip.Marshal(w)
			_, _ = s.c.Write(b)
		}, knx.ErrMalformed},
	} {
		if _, err := secureDial(t, cred, tc.script); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestSecureTransport(t *testing.T) {
	old := sessionKeepAlive
	sessionKeepAlive = 50 * time.Millisecond
	defer func() { sessionKeepAlive = old }()
	dev, _ := secure.DeviceAuthenticationCode("dev")
	cred, _ := secure.NewCredentials(2, "pw", "dev")
	got := make(chan knxnetip.Message, 8)
	st, done, err := secureDialAsync(t, cred, func(s *scripted) {
		s.respond(dev)
		auth := s.read().(*knxnetip.SecureWrapper)
		if _, err := s.sess.Unwrap(auth); err != nil {
			t.Error(err)
		}
		// A frame before the status is skipped by the handshake.
		s.writeWrapped(&knxnetip.SessionStatus{Status: knxnetip.SessionKeepAlive})
		s.writeWrapped(&knxnetip.SessionStatus{Status: knxnetip.SessionAuthSuccess})
		// The client's keep alive.
		if w, ok := s.read().(*knxnetip.SecureWrapper); ok {
			f, err := s.sess.Unwrap(w)
			if err != nil {
				t.Error(err)
			}
			m, _ := knxnetip.Parse(f)
			got <- m
		}
		s.writeWrapped(&knxnetip.SessionStatus{Status: knxnetip.SessionKeepAlive})
		// A frame that fails authentication is dropped.
		bad, _ := s.sess.Wrap([]byte{6, 0x10, 2, 9, 0, 6})
		bad.MAC[0] ^= 1
		s.write(bad)
		s.writeWrapped(&knxnetip.ConnectionStateResponse{Channel: 1})
		s.writeWrapped(&knxnetip.SessionStatus{Status: knxnetip.SessionClose})
		// Read until the client closes: closing with unread data would
		// reset the connection (Windows drops what the client has not
		// read yet).
		_, _ = io.Copy(io.Discard, s.c)
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.localAddr() == nil || !st.stream() {
		t.Error("transport accessors")
	}
	buf := make([]byte, 64)
	n, _, err := st.readFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := knxnetip.Parse(buf[:n]); m == nil || m.Service() != knxnetip.ConnectionStateResponseType {
		t.Errorf("read %v", m)
	}
	if _, _, err := st.readFrom(buf); !errors.Is(err, errSessionClosed) {
		t.Errorf("close status: %v", err)
	}
	select {
	case m := <-got:
		if s, ok := m.(*knxnetip.SessionStatus); !ok || s.Status != knxnetip.SessionKeepAlive {
			t.Errorf("keep alive %v", m)
		}
	default:
		t.Error("no keep alive")
	}
	_ = st.close()
	<-done
	_ = st.close()
	st.sendKeepAlive() // closed: nothing sent
	if _, _, err := st.readFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Errorf("after close: %v", err)
	}
}
