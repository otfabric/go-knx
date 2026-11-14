// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-knx/knxnetip"
)

// tcpConn is a KNXnet/IP connection over TCP (core v2). It carries the
// frames of one client: description, connection management, and the
// tunnelling or device management connections it opens.
type tcpConn struct {
	s      *Server
	c      net.Conn
	remote netip.AddrPort
	wmu    sync.Mutex
	once   sync.Once

	accepted time.Time // start of the authentication deadline
	release  func()    // frees the connection's slot; runs once

	// ss is the KNX IP Secure session, when the client opened one: its
	// frames are wrapped from SESSION_REQUEST on.
	ss sessionState
}

// secured reports whether the client authenticated a secure session, and
// as which user.
func (t *tcpConn) secured() (uint8, bool) {
	if t == nil {
		return 0, false
	}
	return t.ss.secured()
}

func (t *tcpConn) write(m knxnetip.Message) {
	sess := t.ss.session()
	var b []byte
	var err error
	if sess != nil && m.Service() != knxnetip.SessionResponseType {
		b, err = sess.Marshal(m)
	} else {
		b, err = knxnetip.Marshal(m)
	}
	if err != nil {
		// A frame that does not encode can follow from a peer's request.
		t.s.o.logger.Debugf("server: encode %s: %v", m.Service(), err)
		return
	}
	t.wmu.Lock()
	_ = t.c.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = t.c.Write(b)
	t.wmu.Unlock()
	if err != nil {
		t.s.o.logger.Debugf("server: write %s to tcp %s: %v", m.Service(), t.remote, err)
		t.close()
		return
	}
	t.s.o.metrics.OnFrameSent(net.TCPAddrFromAddrPort(t.remote), uint16(m.Service()), len(b))
}

func (t *tcpConn) close() { t.once.Do(func() { _ = t.c.Close() }) }

// acceptLoop accepts TCP connections, at most maxTCP at a time. On a
// secure server, when all are taken, a new connection replaces the oldest
// one that has not authenticated.
func (s *Server) acceptLoop(ln *net.TCPListener) {
	defer s.wg.Done()
	sem := make(chan struct{}, s.maxTCP())
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if !s.acquireTCP(sem) {
			s.o.logger.Warnf("server: refuse tcp %s: too many connections", c.RemoteAddr())
			_ = c.Close()
			continue
		}
		ap := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		t := &tcpConn{s: s, c: c, remote: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), accepted: time.Now(),
			release: sync.OnceFunc(func() { <-sem })}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = c.Close()
			<-sem
			return
		}
		s.tcpConns[t] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serveTCP(t)
	}
}

// acquireTCP takes a slot of the TCP limit. When none is free on a secure
// server, the oldest connection without an authenticated session gives
// its slot up and is closed. Only acceptLoop takes slots, so the slot it
// frees is the one it takes.
func (s *Server) acquireTCP(sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	default:
	}
	if s.o.secure == nil {
		return false
	}
	var oldest *tcpConn
	s.mu.Lock()
	for t := range s.tcpConns {
		if _, ok := t.secured(); !ok && (oldest == nil || t.accepted.Before(oldest.accepted)) {
			oldest = t
		}
	}
	s.mu.Unlock()
	if oldest == nil {
		return false
	}
	oldest.release()
	oldest.close()
	s.o.metrics.OnDropped(net.TCPAddrFromAddrPort(oldest.remote), "session_replaced")
	s.o.logger.Debugf("server: tcp %s replaced: not authenticated", oldest.remote)
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// maxTCP bounds the concurrent TCP connections: one per tunnelling
// address, plus room for description and device management.
func (s *Server) maxTCP() int { return len(s.o.tunnels) + 4 }

// serveTCP reads the frames of one TCP connection until it closes, then
// ends the connections it opened. t.release frees the connection's slot
// of the TCP limit; it runs before the socket is closed, so a peer that
// sees the close finds the slot free.
func (s *Server) serveTCP(t *tcpConn) {
	defer s.wg.Done()
	defer func() {
		t.release()
		t.close()
		s.mu.Lock()
		delete(s.tcpConns, t)
		var opened []*tconn
		for _, c := range s.conns {
			if c.tcp == t {
				opened = append(opened, c)
			}
		}
		s.mu.Unlock()
		for _, c := range opened {
			s.disconnect(c, false, errors.New("the TCP connection closed"))
		}
	}()
	ta := net.TCPAddrFromAddrPort(t.remote)
	for {
		// A client without traffic or heartbeat for the alive time is
		// gone; a secure session ends after the session timeout.
		// On a secure server a connection without an authenticated
		// session ends at the authentication deadline, whatever it sends.
		idle := s.o.aliveTime
		if s.o.secure != nil {
			idle = min(idle, s.o.sessionTimeout)
		}
		deadline := time.Now().Add(idle)
		if _, ok := t.secured(); s.o.secure != nil && !ok {
			if d := t.accepted.Add(s.o.authTimeout); d.Before(deadline) {
				deadline = d
			}
		}
		_ = t.c.SetReadDeadline(deadline)
		b, err := knxnetip.ReadFrame(t.c)
		if err != nil {
			return
		}
		m, err := knxnetip.Parse(b)
		if err != nil {
			// ReadFrame consumed the frame by the total length of its
			// valid header, so the stream is still aligned: drop the
			// frame and read on. A bad header ends the connection above.
			s.o.metrics.OnDecodeError(ta, err)
			s.o.logger.Debugf("server: drop frame from %s: %v", t.remote, err)
			continue
		}
		s.o.metrics.OnFrameReceived(ta, uint16(m.Service()), len(b))
		if s.o.secure != nil {
			if !s.handleSecure(t, m) {
				return
			}
			continue
		}
		s.handle(peer{addr: t.remote, tcp: t}, m)
	}
}
