// SPDX-License-Identifier: MIT

package tunnel

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
)

// sessionKeepAlive is the idle time after which the client sends a
// SESSION_STATUS keep alive; servers end sessions idle for 60 s.
var sessionKeepAlive = 45 * time.Second

// secureTransport carries the frames of a TCP connection or a UDP socket
// in a KNX IP Secure session: every frame is sent and received in a
// SECURE_WRAPPER. Over UDP, frames from other hosts are dropped.
type secureTransport struct {
	inner  transport
	server netip.AddrPort // the server's control endpoint
	sess   *secure.Session
	buf    []byte

	mu        sync.Mutex
	idle      time.Duration // keep alive interval
	keepalive *time.Timer
	closed    bool
}

// errSessionClosed reports a session the server ended.
var errSessionClosed = errors.New("tunnel: the server closed the secure session")

// handshake establishes a secure session with the server's control
// endpoint: the key exchange (SESSION_REQUEST with the client's control
// endpoint hpai, SESSION_RESPONSE), then the user's authentication
// (SESSION_AUTHENTICATE, SESSION_STATUS).
func handshake(t transport, server netip.AddrPort, hpai knxnetip.HPAI, cred secure.Credentials, timeout time.Duration) (*secureTransport, error) {
	kp, err := secure.NewKeyPair()
	if err != nil {
		return nil, err
	}
	_ = t.setDeadline(time.Now().Add(timeout))
	defer func() { _ = t.setDeadline(time.Time{}) }()
	b, err := knxnetip.Marshal(&knxnetip.SessionRequest{Control: hpai, PublicKey: kp.Public})
	if err != nil {
		return nil, err
	}
	if err := t.writeTo(b, server); err != nil {
		return nil, fmt.Errorf("tunnel: send SESSION_REQUEST: %w", err)
	}
	st := &secureTransport{inner: t, server: server, buf: make([]byte, knxnetip.MaxFrameLen+1)}
	m, err := st.readMessage()
	if err != nil {
		return nil, err
	}
	resp, ok := m.(*knxnetip.SessionResponse)
	if !ok {
		if st, ok := m.(*knxnetip.SessionStatus); ok {
			return nil, fmt.Errorf("%w: tunnel: secure session refused, status %d", knx.ErrRejected, st.Status)
		}
		return nil, fmt.Errorf("%w: tunnel: %s instead of SESSION_RESPONSE", knx.ErrSecurity, m.Service())
	}
	if cred.DeviceCode != nil && !secure.Equal(resp.MAC, secure.ResponseMAC(*cred.DeviceCode, resp.SessionID, kp.Public, resp.PublicKey)) {
		return nil, fmt.Errorf("%w: tunnel: SESSION_RESPONSE authentication failed (wrong device authentication code)", knx.ErrSecurity)
	}
	key, err := kp.SessionKey(resp.PublicKey)
	if err != nil {
		return nil, err
	}
	var serial [6]byte
	serial[0], serial[1] = 0x00, 0xFA
	if _, err := rand.Read(serial[2:]); err != nil {
		return nil, err
	}
	st.sess = secure.NewSession(resp.SessionID, key, serial)
	auth := &knxnetip.SessionAuthenticate{UserID: cred.UserID, MAC: secure.AuthenticateMAC(cred.UserKey, cred.UserID, kp.Public, resp.PublicKey)}
	if err := st.send(auth); err != nil {
		return nil, fmt.Errorf("tunnel: send SESSION_AUTHENTICATE: %w", err)
	}
	for {
		m, err := st.readMessage()
		if err != nil {
			return nil, err
		}
		frame, err := st.open(m)
		if err != nil {
			return nil, err
		}
		if m, err = knxnetip.Parse(frame); err != nil {
			return nil, err
		}
		status, ok := m.(*knxnetip.SessionStatus)
		if !ok || status.Status == knxnetip.SessionKeepAlive {
			continue
		}
		if status.Status != knxnetip.SessionAuthSuccess {
			return nil, fmt.Errorf("%w: tunnel: user %d not authenticated, session status %d", knx.ErrSecurity, cred.UserID, status.Status)
		}
		break
	}
	st.mu.Lock()
	st.idle = sessionKeepAlive
	st.keepalive = time.AfterFunc(st.idle, st.sendKeepAlive)
	st.mu.Unlock()
	return st, nil
}

// readMessage reads the next frame of the server during the handshake.
func (t *secureTransport) readMessage() (knxnetip.Message, error) {
	for {
		n, from, err := t.inner.readFrom(t.buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, fmt.Errorf("%w: tunnel: secure session: no answer from %s", knx.ErrTimeout, t.server)
			}
			return nil, fmt.Errorf("%w: tunnel: secure session: %v", knx.ErrConnectionLost, err)
		}
		if !t.inner.stream() && from.Addr() != t.server.Addr() {
			continue
		}
		return knxnetip.Parse(t.buf[:n])
	}
}

// open unwraps a SECURE_WRAPPER of the session; other frames are refused.
func (t *secureTransport) open(m knxnetip.Message) ([]byte, error) {
	w, ok := m.(*knxnetip.SecureWrapper)
	if !ok {
		return nil, fmt.Errorf("%w: tunnel: unencrypted %s in a secure session", knx.ErrSecurity, m.Service())
	}
	return t.sess.Unwrap(w)
}

func (t *secureTransport) send(m knxnetip.Message) error {
	b, err := knxnetip.Marshal(m)
	if err != nil {
		return err
	}
	return t.writeTo(b, t.server)
}

func (t *secureTransport) writeTo(b []byte, to netip.AddrPort) error {
	w, err := t.sess.Wrap(b)
	if err != nil {
		return err
	}
	wb, err := knxnetip.Marshal(w)
	if err != nil {
		return err
	}
	t.mu.Lock()
	if t.keepalive != nil {
		t.keepalive.Reset(t.idle)
	}
	t.mu.Unlock()
	return t.inner.writeTo(wb, to)
}

func (t *secureTransport) sendKeepAlive() {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if !closed {
		_ = t.send(&knxnetip.SessionStatus{Status: knxnetip.SessionKeepAlive})
	}
}

// readFrom returns the next frame of the session. SESSION_STATUS keep
// alives are consumed; a closing status ends the stream. Frames that fail
// authentication, and over UDP frames from other hosts, are dropped.
func (t *secureTransport) readFrom(buf []byte) (int, netip.AddrPort, error) {
	for {
		n, from, err := t.inner.readFrom(t.buf)
		if err != nil {
			return 0, from, err
		}
		if !t.inner.stream() && from.Addr() != t.server.Addr() {
			continue
		}
		m, err := knxnetip.Parse(t.buf[:n])
		if err != nil {
			if t.inner.stream() {
				return 0, from, err
			}
			continue
		}
		frame, err := t.open(m)
		if err != nil {
			continue
		}
		if h, err := knxnetip.ParseHeader(frame); err == nil && h.Service == knxnetip.SessionStatusType {
			if m, err := knxnetip.Parse(frame); err == nil {
				switch m.(*knxnetip.SessionStatus).Status {
				case knxnetip.SessionClose, knxnetip.SessionTimeout, knxnetip.SessionUnauthenticated:
					return 0, from, errSessionClosed
				case knxnetip.SessionAuthSuccess, knxnetip.SessionAuthFailed, knxnetip.SessionKeepAlive:
				}
			}
			continue
		}
		return copy(buf, frame), from, nil
	}
}

// close ends the session (SESSION_STATUS close) and the connection.
func (t *secureTransport) close() error {
	t.mu.Lock()
	already := t.closed
	t.closed = true
	if t.keepalive != nil {
		t.keepalive.Stop()
	}
	t.mu.Unlock()
	if !already {
		_ = t.inner.setDeadline(time.Now().Add(time.Second))
		_ = t.send(&knxnetip.SessionStatus{Status: knxnetip.SessionClose})
	}
	return t.inner.close()
}

func (t *secureTransport) localAddr() net.Addr           { return t.inner.localAddr() }
func (t *secureTransport) stream() bool                  { return t.inner.stream() }
func (t *secureTransport) setDeadline(d time.Time) error { return t.inner.setDeadline(d) }
