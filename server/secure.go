// SPDX-License-Identifier: MIT

package server

import (
	"net"

	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
)

// handleSecure processes a frame of a TCP connection of a secure server.
// It returns false when the connection must close.
func (s *Server) handleSecure(t *tcpConn, m knxnetip.Message) bool {
	ta := net.TCPAddrFromAddrPort(t.remote)
	switch m := m.(type) {
	case *knxnetip.SessionRequest:
		t.smu.Lock()
		started := t.sess != nil
		t.smu.Unlock()
		if started {
			s.o.metrics.OnDropped(ta, "session_started")
			return true
		}
		kp, err := secure.NewKeyPair()
		if err != nil {
			return false
		}
		key, err := kp.SessionKey(m.PublicKey)
		if err != nil {
			s.o.logger.Debugf("server: tcp %s: session request: %v", t.remote, err)
			return false
		}
		s.mu.Lock()
		s.sessionID++
		if s.sessionID == 0 {
			s.sessionID = 1
		}
		id := s.sessionID
		s.mu.Unlock()
		t.smu.Lock()
		t.sess = secure.NewSession(id, key, s.o.serial)
		t.clientPub, t.serverPub = m.PublicKey, kp.Public
		t.smu.Unlock()
		t.write(&knxnetip.SessionResponse{SessionID: id, PublicKey: kp.Public,
			MAC: secure.ResponseMAC(s.o.secure.device, id, m.PublicKey, kp.Public)})
		return true
	case *knxnetip.SecureWrapper:
		t.smu.Lock()
		sess := t.sess
		t.smu.Unlock()
		if sess == nil {
			s.o.metrics.OnDropped(ta, "no_session")
			return false
		}
		frame, err := sess.Unwrap(m)
		if err != nil {
			s.o.metrics.OnDecodeError(ta, err)
			return true
		}
		inner, err := knxnetip.Parse(frame)
		if err != nil {
			s.o.metrics.OnDecodeError(ta, err)
			return true
		}
		return s.handleSession(t, inner)
	case *knxnetip.SearchRequest, *knxnetip.SearchRequestExt, *knxnetip.DescriptionRequest:
		s.handle(peer{addr: t.remote, tcp: t}, m)
		return true
	case *knxnetip.ConnectRequest:
		// A secure interface refuses plain connections.
		t.write(&knxnetip.ConnectResponse{Status: knxnetip.StatusConnectionType})
		return true
	default:
		s.o.metrics.OnDropped(ta, "unsecured")
		return true
	}
}

// handleSession processes a frame received in a secure session.
func (s *Server) handleSession(t *tcpConn, m knxnetip.Message) bool {
	switch m := m.(type) {
	case *knxnetip.SessionAuthenticate:
		t.smu.Lock()
		user, ok := s.o.secure.users[m.UserID]
		ok = ok && secure.Equal(m.MAC, secure.AuthenticateMAC(user.Key, m.UserID, t.clientPub, t.serverPub))
		if ok {
			t.user, t.authed = m.UserID, true
		}
		t.smu.Unlock()
		status := knxnetip.SessionAuthSuccess
		if !ok {
			status = knxnetip.SessionAuthFailed
			s.o.logger.Warnf("server: tcp %s: authentication of user %d failed", t.remote, m.UserID)
		} else {
			s.o.logger.Infof("server: tcp %s: secure session of user %d", t.remote, m.UserID)
		}
		t.write(&knxnetip.SessionStatus{Status: status})
		return true
	case *knxnetip.SessionStatus:
		// Keep alive (the read deadline is renewed) or close.
		return m.Status != knxnetip.SessionClose
	}
	if _, ok := t.secured(); !ok {
		t.write(&knxnetip.SessionStatus{Status: knxnetip.SessionUnauthenticated})
		return true
	}
	s.handle(peer{addr: t.remote, tcp: t}, m)
	return true
}
