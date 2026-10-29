// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
)

// rawSecure is a hand-written secure client of the server.
type rawSecure struct {
	t    *testing.T
	c    net.Conn
	kp   *secure.KeyPair
	resp *knxnetip.SessionResponse
	sess *secure.Session
}

func startSecure(t *testing.T) (*server.Server, string) {
	t.Helper()
	dev, _ := secure.DeviceAuthenticationCode("dev")
	u, _ := secure.UserPasswordKey("pw")
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false),
		server.WithTunnelAddresses(knx.MustParseIndividualAddress("1.1.10")),
		server.WithSecure(dev, map[uint8]server.SecureUser{2: {Key: u}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, s.Addr().String()
}

func dialSecure(t *testing.T, addr string) *rawSecure {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return &rawSecure{t: t, c: c}
}

func (r *rawSecure) write(m knxnetip.Message) {
	b, err := knxnetip.Marshal(m)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.c.Write(b); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawSecure) writeWrapped(m knxnetip.Message) {
	b, err := r.sess.Marshal(m)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.c.Write(b); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawSecure) read() (knxnetip.Message, error) {
	b, err := knxnetip.ReadFrame(r.c)
	if err != nil {
		return nil, err
	}
	m, err := knxnetip.Parse(b)
	if err != nil {
		return nil, err
	}
	if w, ok := m.(*knxnetip.SecureWrapper); ok && r.sess != nil {
		f, err := r.sess.Unwrap(w)
		if err != nil {
			return nil, err
		}
		return knxnetip.Parse(f)
	}
	return m, nil
}

func (r *rawSecure) mustRead() knxnetip.Message {
	r.t.Helper()
	m, err := r.read()
	if err != nil {
		r.t.Fatal(err)
	}
	return m
}

func (r *rawSecure) open() {
	r.t.Helper()
	r.kp, _ = secure.NewKeyPair()
	r.write(&knxnetip.SessionRequest{Control: knxnetip.TCPHPAI(), PublicKey: r.kp.Public})
	resp, ok := r.mustRead().(*knxnetip.SessionResponse)
	if !ok {
		r.t.Fatal("no SESSION_RESPONSE")
	}
	dev, _ := secure.DeviceAuthenticationCode("dev")
	if !secure.Equal(resp.MAC, secure.ResponseMAC(dev, resp.SessionID, r.kp.Public, resp.PublicKey)) {
		r.t.Fatal("SESSION_RESPONSE MAC")
	}
	key, _ := r.kp.SessionKey(resp.PublicKey)
	r.resp, r.sess = resp, secure.NewSession(resp.SessionID, key, [6]byte{})
}

func (r *rawSecure) status() knxnetip.SessionStatusCode {
	r.t.Helper()
	st, ok := r.mustRead().(*knxnetip.SessionStatus)
	if !ok {
		r.t.Fatal("no SESSION_STATUS")
	}
	return st.Status
}

func (r *rawSecure) authenticate(user uint8, pw string) knxnetip.SessionStatusCode {
	r.t.Helper()
	k, _ := secure.UserPasswordKey(pw)
	r.writeWrapped(&knxnetip.SessionAuthenticate{UserID: user, MAC: secure.AuthenticateMAC(k, user, r.kp.Public, r.resp.PublicKey)})
	return r.status()
}

func connectReq() *knxnetip.ConnectRequest {
	return &knxnetip.ConnectRequest{Control: knxnetip.TCPHPAI(), Data: knxnetip.TCPHPAI(),
		CRI: knxnetip.CRI{Type: knxnetip.TunnelConnection, Layer: knxnetip.TunnelLinkLayer}}
}

func TestSecureSession(t *testing.T) {
	_, addr := startSecure(t)
	r := dialSecure(t, addr)
	// Plain connection requests are refused; description stays plain.
	r.write(connectReq())
	if cr, ok := r.mustRead().(*knxnetip.ConnectResponse); !ok || cr.Status != knxnetip.StatusConnectionType {
		t.Fatalf("plain connect: %+v", cr)
	}
	r.write(&knxnetip.DescriptionRequest{Control: knxnetip.TCPHPAI()})
	d, ok := r.mustRead().(*knxnetip.DescriptionResponse)
	if !ok {
		t.Fatal("no description")
	}
	secured := false
	for _, dib := range d.DIBs {
		if f, ok := dib.(knxnetip.ServiceFamilies); ok && f.Secured {
			secured = true
		}
	}
	if !secured {
		t.Error("no secured service families DIB")
	}
	r.write(&knxnetip.ConnectionStateRequest{Channel: 1, Control: knxnetip.TCPHPAI()}) // dropped
	r.open()
	// A second SESSION_REQUEST is ignored.
	r.write(&knxnetip.SessionRequest{Control: knxnetip.TCPHPAI(), PublicKey: r.kp.Public})
	// Before authentication: unauthenticated.
	r.writeWrapped(connectReq())
	if st := r.status(); st != knxnetip.SessionUnauthenticated {
		t.Errorf("connect before authentication: status %d", st)
	}
	if st := r.authenticate(2, "wrong"); st != knxnetip.SessionAuthFailed {
		t.Errorf("wrong password: status %d", st)
	}
	if st := r.authenticate(2, "pw"); st != knxnetip.SessionAuthSuccess {
		t.Fatalf("authentication: status %d", st)
	}
	// A wrapper that fails authentication is dropped.
	bad, _ := r.sess.Wrap([]byte{6, 0x10, 2, 9, 0, 6})
	bad.MAC[0] ^= 1
	r.write(bad)
	// A wrapped frame that does not parse is dropped.
	w, _ := r.sess.Wrap([]byte{6, 0x10, 2, 5, 0, 6})
	r.write(w)
	r.writeWrapped(&knxnetip.SessionStatus{Status: knxnetip.SessionKeepAlive})
	// Device management is for user 1 only.
	dm := connectReq()
	dm.CRI = knxnetip.CRI{Type: knxnetip.DeviceManagementConnection}
	r.writeWrapped(dm)
	if cr, ok := r.mustRead().(*knxnetip.ConnectResponse); !ok || cr.Status != knxnetip.StatusConnectionType {
		t.Fatalf("device management as user 2: %+v", cr)
	}
	r.writeWrapped(connectReq())
	cr, ok := r.mustRead().(*knxnetip.ConnectResponse)
	if !ok || cr.Status != knxnetip.StatusNoError || cr.CRD.Address != knx.MustParseIndividualAddress("1.1.10") {
		t.Fatalf("secure connect: %+v", cr)
	}
	// Closing the session closes the connection.
	r.writeWrapped(&knxnetip.SessionStatus{Status: knxnetip.SessionClose})
	for {
		if _, err := r.read(); err != nil {
			break
		}
	}
}

func TestSecureSessionErrors(t *testing.T) {
	_, addr := startSecure(t)
	// A SECURE_WRAPPER without a session closes the connection.
	r := dialSecure(t, addr)
	w, _ := secure.Seal(secure.Key{}, 1, 0, [6]byte{}, 0, []byte{6, 0x10, 2, 9, 0, 6})
	r.write(w)
	if _, err := r.read(); err == nil {
		t.Error("connection open after a wrapper without session")
	}
	// A low order public key closes the connection.
	r = dialSecure(t, addr)
	r.write(&knxnetip.SessionRequest{Control: knxnetip.TCPHPAI()})
	if _, err := r.read(); err == nil {
		t.Error("connection open after an invalid public key")
	}
	// Plain UDP connections are refused too.
	u, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	la := u.LocalAddr().(*net.UDPAddr).AddrPort()
	b, _ := knxnetip.Marshal(&knxnetip.ConnectRequest{Control: knxnetip.NewHPAI(la), Data: knxnetip.NewHPAI(la),
		CRI: knxnetip.CRI{Type: knxnetip.TunnelConnection, Layer: knxnetip.TunnelLinkLayer}})
	_, _ = u.Write(b)
	_ = u.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := knxnetip.Parse(buf[:n])
	if cr, ok := m.(*knxnetip.ConnectResponse); !ok || cr.Status != knxnetip.StatusConnectionType {
		t.Errorf("plain UDP connect: %+v", m)
	}
}
