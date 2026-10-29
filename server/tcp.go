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
}

func (t *tcpConn) write(m knxnetip.Message) {
	b, err := knxnetip.Marshal(m)
	if err != nil {
		t.s.o.logger.Errorf("server: encode %s: %v", m.Service(), err)
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

// acceptLoop accepts TCP connections, at most maxTCP at a time.
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
		select {
		case sem <- struct{}{}:
		default:
			s.o.logger.Warnf("server: refuse tcp %s: too many connections", c.RemoteAddr())
			_ = c.Close()
			continue
		}
		ap := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		t := &tcpConn{s: s, c: c, remote: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
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
		go func() {
			defer func() { <-sem }()
			s.serveTCP(t)
		}()
	}
}

// maxTCP bounds the concurrent TCP connections: one per tunnelling
// address, plus room for description and device management.
func (s *Server) maxTCP() int { return len(s.o.tunnels) + 4 }

// serveTCP reads the frames of one TCP connection until it closes, then
// ends the connections it opened.
func (s *Server) serveTCP(t *tcpConn) {
	defer s.wg.Done()
	defer func() {
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
		// A client without traffic or heartbeat for the alive time is gone.
		_ = t.c.SetReadDeadline(time.Now().Add(s.o.aliveTime))
		b, err := knxnetip.ReadFrame(t.c)
		if err != nil {
			return
		}
		m, err := knxnetip.Parse(b)
		if err != nil {
			s.o.metrics.OnDecodeError(ta, err)
			return // a stream cannot resynchronise
		}
		s.o.metrics.OnFrameReceived(ta, uint16(m.Service()), len(b))
		s.handle(peer{addr: t.remote, tcp: t}, m)
	}
}
