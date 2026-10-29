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

// secureTransport carries the frames of a TCP connection in a KNX IP
// Secure session: every frame is sent and received in a SECURE_WRAPPER.
type secureTransport struct {
	inner *tcpTransport
	sess  *secure.Session

	mu        sync.Mutex
	idle      time.Duration // keep alive interval
	keepalive *time.Timer
	closed    bool
}

// errSessionClosed reports a session the server ended.
var errSessionClosed = errors.New("tunnel: the server closed the secure session")

// handshake establishes a secure session on a TCP connection: the key
// exchange (SESSION_REQUEST, SESSION_RESPONSE), then the user's
// authentication (SESSION_AUTHENTICATE, SESSION_STATUS).
func handshake(t *tcpTransport, cred secure.Credentials, timeout time.Duration) (*secureTransport, error) {
	kp, err := secure.NewKeyPair()
	if err != nil {
		return nil, err
	}
	_ = t.c.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = t.c.SetDeadline(time.Time{}) }()
	b, err := knxnetip.Marshal(&knxnetip.SessionRequest{Control: knxnetip.TCPHPAI(), PublicKey: kp.Public})
	if err != nil {
		return nil, err
	}
	if err := t.writeTo(b, t.server); err != nil {
		return nil, fmt.Errorf("tunnel: send SESSION_REQUEST: %w", err)
	}
	m, err := readMessage(t)
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
	st := &secureTransport{inner: t, sess: secure.NewSession(resp.SessionID, key, serial)}
	auth := &knxnetip.SessionAuthenticate{UserID: cred.UserID, MAC: secure.AuthenticateMAC(cred.UserKey, cred.UserID, kp.Public, resp.PublicKey)}
	if err := st.send(auth); err != nil {
		return nil, fmt.Errorf("tunnel: send SESSION_AUTHENTICATE: %w", err)
	}
	for {
		m, err := readMessage(t)
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

func readMessage(t *tcpTransport) (knxnetip.Message, error) {
	f, err := knxnetip.ReadFrame(t.c)
	if err != nil {
		return nil, fmt.Errorf("%w: tunnel: secure session: %v", knx.ErrConnectionLost, err)
	}
	return knxnetip.Parse(f)
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
	return t.writeTo(b, t.inner.server)
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
// alives are consumed; a closing status ends the stream.
func (t *secureTransport) readFrom(buf []byte) (int, netip.AddrPort, error) {
	for {
		f, err := knxnetip.ReadFrame(t.inner.c)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return 0, t.inner.server, err
			}
			return 0, t.inner.server, errStreamClosed
		}
		m, err := knxnetip.Parse(f)
		if err != nil {
			return 0, t.inner.server, err
		}
		frame, err := t.open(m)
		if err != nil {
			// A frame that fails authentication is dropped; the stream
			// itself is intact.
			continue
		}
		if h, err := knxnetip.ParseHeader(frame); err == nil && h.Service == knxnetip.SessionStatusType {
			if m, err := knxnetip.Parse(frame); err == nil {
				switch m.(*knxnetip.SessionStatus).Status {
				case knxnetip.SessionClose, knxnetip.SessionTimeout, knxnetip.SessionUnauthenticated:
					return 0, t.inner.server, errSessionClosed
				case knxnetip.SessionAuthSuccess, knxnetip.SessionAuthFailed, knxnetip.SessionKeepAlive:
				}
			}
			continue
		}
		return copy(buf, frame), t.inner.server, nil
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
		_ = t.inner.c.SetWriteDeadline(time.Now().Add(time.Second))
		_ = t.send(&knxnetip.SessionStatus{Status: knxnetip.SessionClose})
	}
	return t.inner.close()
}

func (t *secureTransport) localAddr() net.Addr { return t.inner.localAddr() }
func (*secureTransport) stream() bool          { return true }
