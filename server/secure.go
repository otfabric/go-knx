// SPDX-License-Identifier: MIT

package server

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
)

// sessionState is a KNX IP Secure session of a client: over TCP the
// session of its connection, over UDP a session of its own.
type sessionState struct {
	mu        sync.Mutex
	sess      *secure.Session
	clientPub [32]byte
	serverPub [32]byte
	user      uint8
	authed    bool
	lastSeen  time.Time
}

func (st *sessionState) secured() (uint8, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.user, st.authed
}

func (st *sessionState) session() *secure.Session {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sess
}

// udpSession is a secure session over UDP: its frames come from the
// client's address and carry its session identifier.
type udpSession struct {
	id   uint16
	ctrl netip.AddrPort // where SESSION_* frames are answered
	ss   sessionState
}

// secured reports the authenticated user of a peer's secure session.
func (p peer) secured() (uint8, bool) {
	switch {
	case p.tcp != nil:
		return p.tcp.secured()
	case p.us != nil:
		return p.us.ss.secured()
	}
	return 0, false
}

// start answers a SESSION_REQUEST: the server's key pair, the session
// key and the SESSION_RESPONSE.
func (s *Server) start(st *sessionState, m *knxnetip.SessionRequest) (*knxnetip.SessionResponse, error) {
	kp, err := secure.NewKeyPair()
	if err != nil {
		return nil, err
	}
	key, err := kp.SessionKey(m.PublicKey)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	for {
		s.sessionID++
		if _, taken := s.usessions[s.sessionID]; s.sessionID != 0 && !taken {
			break
		}
	}
	id := s.sessionID
	s.mu.Unlock()
	st.mu.Lock()
	st.sess = secure.NewSession(id, key, s.o.serial)
	st.clientPub, st.serverPub = m.PublicKey, kp.Public
	st.lastSeen = time.Now()
	st.mu.Unlock()
	return &knxnetip.SessionResponse{SessionID: id, PublicKey: kp.Public,
		MAC: secure.ResponseMAC(s.o.secure.device, id, m.PublicKey, kp.Public)}, nil
}

// handleSecure processes a frame of a TCP connection of a secure server.
// It returns false when the connection must close.
func (s *Server) handleSecure(t *tcpConn, m knxnetip.Message) bool {
	ta := net.TCPAddrFromAddrPort(t.remote)
	switch m := m.(type) {
	case *knxnetip.SessionRequest:
		if t.ss.session() != nil {
			s.o.metrics.OnDropped(ta, "session_started")
			return true
		}
		resp, err := s.start(&t.ss, m)
		if err != nil {
			s.o.logger.Debugf("server: tcp %s: session request: %v", t.remote, err)
			return false
		}
		t.write(resp)
		return true
	case *knxnetip.SecureWrapper:
		sess := t.ss.session()
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
		return s.handleSession(&t.ss, t.write, peer{addr: t.remote, tcp: t}, inner)
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

// handleSession processes a frame received in a secure session; write
// sends a frame in the session. It returns false when the session ends.
func (s *Server) handleSession(st *sessionState, write func(knxnetip.Message), p peer, m knxnetip.Message) bool {
	st.mu.Lock()
	st.lastSeen = time.Now()
	st.mu.Unlock()
	switch m := m.(type) {
	case *knxnetip.SessionAuthenticate:
		st.mu.Lock()
		user, ok := s.o.secure.users[m.UserID]
		ok = ok && secure.Equal(m.MAC, secure.AuthenticateMAC(user.Key, m.UserID, st.clientPub, st.serverPub))
		if ok {
			st.user, st.authed = m.UserID, true
		}
		st.mu.Unlock()
		status := knxnetip.SessionAuthSuccess
		if !ok {
			status = knxnetip.SessionAuthFailed
			s.o.logger.Warnf("server: %s: authentication of user %d failed", p.addr, m.UserID)
		} else {
			s.o.logger.Infof("server: %s: secure session of user %d", p.addr, m.UserID)
		}
		write(&knxnetip.SessionStatus{Status: status})
		return true
	case *knxnetip.SessionStatus:
		// Keep alive (lastSeen is renewed) or close.
		return m.Status != knxnetip.SessionClose
	}
	if _, ok := st.secured(); !ok {
		write(&knxnetip.SessionStatus{Status: knxnetip.SessionUnauthenticated})
		return true
	}
	s.handle(p, m)
	return true
}

// handleUDPSecure processes the secure frames of the UDP sockets:
// SESSION_REQUEST and SECURE_WRAPPER of sessions over UDP, and the frames
// of secure routing. It reports whether it consumed the frame.
func (s *Server) handleUDPSecure(from netip.AddrPort, m knxnetip.Message) bool {
	fa := net.UDPAddrFromAddrPort(from)
	switch m := m.(type) {
	case *knxnetip.SessionRequest:
		if s.o.secure == nil {
			s.o.metrics.OnDropped(fa, "no_security")
			return true
		}
		us := &udpSession{ctrl: reply(m.Control, from)}
		resp, err := s.start(&us.ss, m)
		if err != nil {
			s.o.logger.Debugf("server: %s: session request: %v", from, err)
			return true
		}
		us.id = resp.SessionID
		s.mu.Lock()
		if len(s.usessions) >= s.maxTCP() {
			s.mu.Unlock()
			s.o.logger.Warnf("server: refuse secure session of %s: too many sessions", from)
			return true
		}
		s.usessions[us.id] = us
		s.mu.Unlock()
		s.write(us.ctrl, resp)
		return true
	case *knxnetip.TimerNotify:
		if s.rtimer != nil && !s.rtimer.HandleNotify(m) {
			s.o.metrics.OnDropped(fa, "authentication")
		}
		return true
	case *knxnetip.SecureWrapper:
		if m.SessionID == 0 {
			s.onSecureRouting(from, m)
			return true
		}
		s.mu.Lock()
		us := s.usessions[m.SessionID]
		s.mu.Unlock()
		if us == nil || us.ctrl.Addr() != from.Addr() {
			s.o.metrics.OnDropped(fa, "session")
			return true
		}
		frame, err := us.ss.session().Unwrap(m)
		if err != nil {
			s.o.metrics.OnDecodeError(fa, err)
			return true
		}
		inner, err := knxnetip.Parse(frame)
		if err != nil {
			s.o.metrics.OnDecodeError(fa, err)
			return true
		}
		write := func(r knxnetip.Message) { s.writeSession(us, us.ctrl, r) }
		if !s.handleSession(&us.ss, write, peer{addr: from, us: us}, inner) {
			s.endSession(us, nil)
		}
		return true
	case *knxnetip.RoutingIndication, *knxnetip.RoutingBusy, *knxnetip.RoutingLostMessage:
		if s.rtimer != nil {
			// Secure routing accepts wrapped frames only.
			s.o.metrics.OnDropped(fa, "unsecured")
			return true
		}
	}
	return false
}

// writeSession sends a frame in a UDP session.
func (s *Server) writeSession(us *udpSession, to netip.AddrPort, m knxnetip.Message) {
	b, err := us.ss.session().Marshal(m)
	if err != nil {
		s.o.logger.Errorf("server: encode %s: %v", m.Service(), err)
		return
	}
	s.writeRaw(to, b, m.Service())
}

// endSession removes a UDP session and the connections opened in it.
func (s *Server) endSession(us *udpSession, cause error) {
	s.mu.Lock()
	delete(s.usessions, us.id)
	var opened []*tconn
	for _, c := range s.conns {
		if c.us == us {
			opened = append(opened, c)
		}
	}
	s.mu.Unlock()
	for _, c := range opened {
		s.disconnect(c, cause != nil, cause)
	}
}

// expireSessions ends UDP sessions without frames for the alive time.
func (s *Server) expireSessions() {
	s.mu.Lock()
	var stale []*udpSession
	for _, us := range s.usessions {
		us.ss.mu.Lock()
		if time.Since(us.ss.lastSeen) > s.o.aliveTime {
			stale = append(stale, us)
		}
		us.ss.mu.Unlock()
	}
	s.mu.Unlock()
	for _, us := range stale {
		s.endSession(us, fmt.Errorf("%w: secure session idle for %v", knx.ErrConnectionLost, s.o.aliveTime))
	}
}

// onSecureRouting opens a SECURE_WRAPPER of secure routing.
func (s *Server) onSecureRouting(from netip.AddrPort, w *knxnetip.SecureWrapper) {
	fa := net.UDPAddrFromAddrPort(from)
	if s.rtimer == nil {
		s.o.metrics.OnDropped(fa, "no_security")
		return
	}
	if !s.rtimer.Authenticated() {
		s.o.metrics.OnDropped(fa, "timer_unsynchronised")
		return
	}
	frame, err := secure.Open(s.o.secureRouting.key, w)
	if err != nil {
		s.o.metrics.OnDecodeError(fa, err)
		return
	}
	if !s.rtimer.Accept(w) {
		s.o.metrics.OnDropped(fa, "timer")
		return
	}
	inner, err := knxnetip.Parse(frame)
	if err != nil {
		s.o.metrics.OnDecodeError(fa, err)
		return
	}
	switch inner.(type) {
	case *knxnetip.RoutingIndication, *knxnetip.RoutingBusy, *knxnetip.RoutingLostMessage:
		s.handle(peer{addr: from}, inner)
	default:
		s.o.metrics.OnDropped(fa, "unexpected")
	}
}

// writeRouting sends a routing frame to the multicast group, in a
// SECURE_WRAPPER with secure routing.
func (s *Server) writeRouting(m knxnetip.Message) {
	if s.rtimer == nil {
		s.write(s.group, m)
		return
	}
	b, err := knxnetip.Marshal(m)
	if err != nil {
		return
	}
	var tag [2]byte
	_, _ = rand.Read(tag[:])
	w, err := secure.Seal(s.o.secureRouting.key, 0, s.rtimer.Next(), s.o.serial, uint16(tag[0])<<8|uint16(tag[1]), b)
	if err != nil {
		s.o.logger.Errorf("server: seal %s: %v", m.Service(), err)
		return
	}
	s.write(s.group, w)
}
