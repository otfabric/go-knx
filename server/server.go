// SPDX-License-Identifier: MIT

// Package server is a KNXnet/IP server: it answers discovery (search,
// extended search) and description requests, accepts tunnelling
// connections from KNXnet/IP clients, and optionally routes over IP
// multicast. Behind it is a virtual KNX network instead of a physical
// line: telegrams of one client are confirmed to it and delivered to the
// other clients, to the virtual devices (package device) and, with
// routing, to the multicast group.
//
// What it implements: core services (search, extended search,
// description, connect, connection state, disconnect), tunnelling on the
// link layer over UDP (KNXnet/IP tunnelling v1, including the extended
// CRI that requests an address) and routing indications. Not implemented
// (refused with the standard status codes): busmonitor and raw
// tunnelling, device management connections, KNXnet/IP over TCP,
// tunnelling feature services, KNX IP Secure. It is not an emulation of
// a KNX TP line or of a physical device's management.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/internal/mcast"
	"github.com/otfabric/go-knx/internal/ratelimit"
	"github.com/otfabric/go-knx/internal/udp"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/mgmt"
	"github.com/otfabric/go-knx/secure"
)

// Origin tells where a telegram came from.
type Origin int

// Origins of telegrams.
const (
	// FromTunnel is a telegram a tunnelling client sent.
	FromTunnel Origin = iota
	// FromRouting is a routing indication from the multicast group.
	FromRouting
	// FromDevice is a telegram of a virtual device.
	FromDevice
	// FromServer is a telegram the application sent with [Server.Send].
	FromServer
)

// Telegram is a telegram on the server's virtual network.
type Telegram struct {
	Origin Origin
	// Channel is the tunnelling channel of a FromTunnel telegram.
	Channel uint8
	Frame   *cemi.LData
}

// Connection describes a tunnelling connection.
type Connection struct {
	Channel  uint8
	Address  knx.IndividualAddress
	Control  netip.AddrPort
	Data     netip.AddrPort
	LastSeen time.Time
}

// Server is a KNXnet/IP server.
type Server struct {
	o       options
	main    *net.UDPConn
	disc    *net.UDPConn // multicast listener when main cannot join
	group   netip.AddrPort
	ifIP    netip.Addr
	routing *ratelimit.Bucket

	tcpLn     *net.TCPListener
	tcpConns  map[*tcpConn]struct{}
	props     *propStore
	mgmt      *mgmt.Responder
	startTime time.Time

	nameMu sync.Mutex
	name   string // the friendly name, writable by device management

	mu      sync.Mutex
	conns   map[uint8]*tconn
	next    uint8
	devices []*device.Device
	taps    map[int]func(Telegram)
	tapID   int
	started bool
	closed  bool

	sessionID uint16 // last secure session identifier
	usessions map[uint16]*udpSession
	rtimer    *secure.RoutingTimer // secure routing
	closing   chan struct{}
	wg        sync.WaitGroup
}

// New returns a server; [Server.Start] or [Server.Serve] opens its
// sockets.
func New(opts ...Option) (*Server, error) {
	o := defaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	if o.secure != nil {
		if !o.tcp {
			return nil, invalid("WithSecure needs TCP (WithTCP(true))")
		}
		for id, u := range o.secure.users {
			if u.Address == 0 {
				continue
			}
			ours := false
			for _, a := range o.tunnels {
				ours = ours || a == u.Address
			}
			if !ours {
				return nil, invalid("secure user %d: %s is not a tunnelling address", id, u.Address)
			}
		}
	}
	if o.secureRouting != nil && !o.routing {
		return nil, invalid("WithSecureRouting needs WithRouting(true)")
	}
	s := &Server{o: o, usessions: map[uint16]*udpSession{}, conns: map[uint8]*tconn{}, tcpConns: map[*tcpConn]struct{}{}, taps: map[int]func(Telegram){}, closing: make(chan struct{}), routing: ratelimit.New(o.routingRate), startTime: time.Now()}
	s.props = &propStore{s: s}
	s.name = o.name
	s.mgmt = &mgmt.Responder{Address: o.address, Descriptor: DeviceDescriptor, Properties: s.props}
	if o.toolKey != nil {
		t, err := datasecure.NewTable(nil, nil, 0)
		if err != nil {
			return nil, err
		}
		t.SetToolKey(o.address, *o.toolKey)
		s.mgmt.Security = t
	}
	return s, nil
}

// AddDevice adds a virtual device to the network.
func (s *Server) AddDevice(d *device.Device) {
	s.mu.Lock()
	s.devices = append(s.devices, d)
	s.mu.Unlock()
}

// Subscribe calls f, synchronously, for every telegram on the virtual
// network; it must not block. The returned function removes it.
func (s *Server) Subscribe(f func(Telegram)) (cancel func()) {
	s.mu.Lock()
	s.tapID++
	id := s.tapID
	s.taps[id] = f
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.taps, id)
		s.mu.Unlock()
	}
}

// Start opens the sockets and starts serving in the background.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("%w: server: already started", knx.ErrInvalidOption)
	}
	s.started = true
	s.mu.Unlock()

	listen, err := udp.ResolveEndpoint(ctx, s.o.listen, knxnetip.Port)
	if err != nil {
		return err
	}
	if s.group, err = udp.ResolveEndpoint(ctx, s.o.group, knxnetip.Port); err != nil {
		return err
	}
	if !s.group.Addr().IsMulticast() {
		return invalid("multicast group %s", s.group)
	}
	var ifi *net.Interface
	if s.o.iface != "" {
		if ifi, s.ifIP, err = udp.InterfaceIPv4(s.o.iface); err != nil {
			return err
		}
	}
	discGroup := netip.AddrPortFrom(knxnetip.MulticastAddress, knxnetip.Port)
	needGroup := s.o.routing || s.o.discovery
	sameSocket := needGroup && (listen.Addr().IsUnspecified() && listen.Port() == s.group.Port() &&
		(!s.o.discovery || !s.o.routing || s.group.Port() == knxnetip.Port))
	// The sockets are published under s.mu, so that Addr and Close may
	// run concurrently with Start (Serve in another goroutine).
	var main, disc *net.UDPConn
	var preTCP *net.TCPListener // bound with an ephemeral UDP port
	if sameSocket {
		join := s.group
		if !s.o.routing {
			join = discGroup
		}
		if main, err = mcast.Listen(ifi, join, false, s.o.ttl); err != nil {
			return fmt.Errorf("server: %w", err)
		}
		if s.ifIP.IsValid() {
			ip := s.ifIP
			_ = mcast.Configure(main, &ip, false, s.o.ttl)
		}
	} else {
		if main, preTCP, err = listenUDPTCP(listen, s.o.tcp); err != nil {
			return fmt.Errorf("server: listen %s: %w", listen, err)
		}
		if s.o.routing {
			_ = main.Close()
			return invalid("routing needs the listen port to be the multicast group's port %d", s.group.Port())
		}
		if s.o.discovery {
			if disc, err = mcast.Listen(ifi, discGroup, false, 1); err != nil {
				s.o.logger.Warnf("server: discovery disabled: %v", err)
				disc = nil
			}
		}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = main.Close()
		if disc != nil {
			_ = disc.Close()
		}
		if preTCP != nil {
			_ = preTCP.Close()
		}
		return knx.ErrClosed
	}
	s.main, s.disc = main, disc
	// TCP (core v2) on the same address and port as UDP.
	if s.o.tcp && preTCP != nil {
		s.tcpLn = preTCP
	} else if s.o.tcp {
		la := udp.AddrPortOf(main.LocalAddr())
		ln, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(la))
		if err != nil {
			s.o.logger.Warnf("server: TCP disabled: %v", err)
			s.o.tcp = false
		} else {
			s.tcpLn = ln
		}
	}
	s.wg.Add(2)
	if disc != nil {
		s.wg.Add(1)
	}
	if s.tcpLn != nil {
		s.wg.Add(1)
	}
	s.mu.Unlock()
	s.o.logger.Infof("server: listening on %s (tcp %t, discovery %t, routing %t)", main.LocalAddr(), s.o.tcp, s.o.discovery, s.o.routing)
	if s.o.routing && s.o.secureRouting != nil {
		s.rtimer = secure.NewRoutingTimer(s.o.secureRouting.key, s.o.serial, s.o.secureRouting.latency, func(m *knxnetip.TimerNotify) { s.write(s.group, m) })
	}
	go s.readLoop(main)
	if s.rtimer != nil {
		go s.rtimer.Synchronize(ctx)
	}
	go s.janitor()
	if disc != nil {
		go s.readLoop(disc)
	}
	if s.tcpLn != nil {
		go s.acceptLoop(s.tcpLn)
	}
	return nil
}

// listenUDPTCP opens the UDP socket and, with tcp, the TCP listener on the
// same port. With port 0 it tries ephemeral ports until both are free (a
// free UDP port may be taken for TCP). With a fixed port the TCP listener
// is opened later by Start.
func listenUDPTCP(listen netip.AddrPort, tcp bool) (*net.UDPConn, *net.TCPListener, error) {
	if listen.Port() != 0 || !tcp {
		c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listen))
		return c, nil, err
	}
	var last error
	for i := 0; i < 20; i++ {
		c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listen))
		if err != nil {
			return nil, nil, err
		}
		ln, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(udp.AddrPortOf(c.LocalAddr())))
		if err == nil {
			return c, ln, nil
		}
		last = err
		_ = c.Close()
	}
	return nil, nil, fmt.Errorf("no port free for UDP and TCP: %w", last)
}

// busmonitorFrame returns the L_Busmon.ind of a telegram for busmonitor
// connections: the TP1 frame with a status and a timestamp (milliseconds
// since the server started, modulo 2^16). Extended frames have no TP1
// standard format and are not monitored.
func (s *Server) busmonitorFrame(f *cemi.LData) []byte {
	raw, err := cemi.TP1Frame(f)
	if err != nil {
		return nil
	}
	ms := uint16(time.Since(s.startTime).Milliseconds())
	b, err := cemi.Marshal(&cemi.Raw{MsgCode: cemi.LBusmonInd, AddInfo: []cemi.AdditionalInfo{
		{Type: cemi.AddInfoBusmonitorStatus, Data: []byte{0x00}},
		{Type: cemi.AddInfoTimestamp, Data: []byte{byte(ms >> 8), byte(ms)}},
	}, Data: raw})
	if err != nil {
		return nil
	}
	return b
}

// Serve starts the server and blocks until ctx is done, then closes it.
func (s *Server) Serve(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-s.closing:
	}
	return s.Close()
}

// Addr returns the local endpoint of the server's socket.
func (s *Server) Addr() netip.AddrPort {
	s.mu.Lock()
	main := s.main
	s.mu.Unlock()
	if main == nil {
		return netip.AddrPort{}
	}
	return udp.AddrPortOf(main.LocalAddr())
}

// Connections returns the open tunnelling connections.
func (s *Server) Connections() []Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Connection, 0, len(s.conns))
	for _, c := range s.conns {
		c.mu.Lock()
		out = append(out, Connection{Channel: c.channel, Address: c.addr, Control: c.ctrl, Data: c.data, LastSeen: c.lastSeen})
		c.mu.Unlock()
	}
	return out
}

// Close disconnects every client, stops the goroutines and closes the
// sockets.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conns := make([]*tconn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	main, disc, ln := s.main, s.disc, s.tcpLn
	tcps := make([]*tcpConn, 0, len(s.tcpConns))
	for t := range s.tcpConns {
		tcps = append(tcps, t)
	}
	s.mu.Unlock()
	for _, c := range conns {
		s.disconnect(c, true, nil)
	}
	if s.rtimer != nil {
		s.rtimer.Stop()
	}
	close(s.closing)
	if ln != nil {
		_ = ln.Close()
	}
	for _, t := range tcps {
		t.close()
	}
	if main != nil {
		_ = main.Close()
	}
	if disc != nil {
		_ = disc.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) write(to netip.AddrPort, m knxnetip.Message) {
	b, err := knxnetip.Marshal(m)
	if err != nil {
		s.o.logger.Errorf("server: encode %s: %v", m.Service(), err)
		return
	}
	s.writeRaw(to, b, m.Service())
}

// writeRaw sends an encoded frame from the main socket.
func (s *Server) writeRaw(to netip.AddrPort, b []byte, service knxnetip.ServiceType) {
	// A write deadline: a multicast send the system blocks must not stall
	// the reader and the distribution.
	_ = s.main.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := s.main.WriteToUDPAddrPort(b, to); err != nil {
		s.o.logger.Debugf("server: write %s to %s: %v", service, to, err)
		return
	}
	s.o.metrics.OnFrameSent(net.UDPAddrFromAddrPort(to), uint16(service), len(b))
}

// endpoint returns the server's endpoint as seen from peer.
func (s *Server) endpoint(peer netip.AddrPort) knxnetip.HPAI {
	ip := s.ifIP
	if !ip.IsValid() {
		if la := udp.AddrPortOf(s.main.LocalAddr()); la.Addr().IsValid() && !la.Addr().IsUnspecified() {
			ip = la.Addr()
		} else if x, err := udp.LocalIPFor(peer); err == nil {
			ip = x
		}
	}
	return knxnetip.NewHPAI(netip.AddrPortFrom(ip, s.Addr().Port()))
}

// dataEndpoint is the data endpoint announced in a CONNECT_RESPONSE. A
// client that asked for route back (NAT) gets the route back endpoint
// 0.0.0.0:0 too: behind NAT the server's own address is not the one the
// client reaches it by, and the client keeps sending to where it sent the
// CONNECT_REQUEST.
func (s *Server) dataEndpoint(m *knxnetip.ConnectRequest, from netip.AddrPort) knxnetip.HPAI {
	if m.Control.IsRouteBack() || m.Data.IsRouteBack() {
		return knxnetip.RouteBackHPAI()
	}
	return s.endpoint(from)
}

func (s *Server) readLoop(c *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, knxnetip.MaxFrameLen+1)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		fa := net.UDPAddrFromAddrPort(from)
		m, err := knxnetip.Parse(buf[:n])
		if err != nil {
			s.o.metrics.OnDecodeError(fa, err)
			s.o.logger.Debugf("server: drop datagram from %s: %v", from, err)
			continue
		}
		s.o.metrics.OnFrameReceived(fa, uint16(m.Service()), n)
		if s.handleUDPSecure(from, m) {
			continue
		}
		s.handle(peer{addr: from}, m)
	}
}

func reply(h knxnetip.HPAI, from netip.AddrPort) netip.AddrPort {
	if h.IsRouteBack() {
		return from
	}
	return h.Addr
}

// reply answers a peer: over its TCP connection, or over UDP to the
// endpoint of h (the source of the datagram for route back endpoints).
func (s *Server) reply(p peer, h knxnetip.HPAI, m knxnetip.Message) {
	if p.tcp != nil {
		p.tcp.write(m)
		return
	}
	if p.us != nil {
		s.writeSession(p.us, reply(h, p.addr), m)
		return
	}
	s.write(reply(h, p.addr), m)
}

func (s *Server) handle(p peer, m knxnetip.Message) {
	from := p.addr
	switch m := m.(type) {
	case *knxnetip.SearchRequest:
		if m.Discovery.Protocol != knxnetip.IPv4UDP || p.tcp != nil {
			return
		}
		s.write(reply(m.Discovery, from), &knxnetip.SearchResponse{Control: s.endpoint(from), DIBs: s.dibs(nil, false)})
	case *knxnetip.SearchRequestExt:
		if dibs, ok := s.searchExt(m); ok {
			switch {
			case p.tcp != nil:
				// A search over TCP (core v2) is answered on the connection.
				p.tcp.write(&knxnetip.SearchResponse{Extended: true, Control: knxnetip.TCPHPAI(), DIBs: dibs})
			case m.Discovery.Protocol == knxnetip.IPv4UDP:
				s.write(reply(m.Discovery, from), &knxnetip.SearchResponse{Extended: true, Control: s.endpoint(from), DIBs: dibs})
			}
		}
	case *knxnetip.DescriptionRequest:
		s.reply(p, m.Control, &knxnetip.DescriptionResponse{DIBs: s.dibs(nil, false)})
	case *knxnetip.ConnectRequest:
		s.onConnect(p, m)
	case *knxnetip.ConnectionStateRequest:
		st := knxnetip.StatusConnectionID
		if c := s.conn(m.Channel); c != nil && c.from(p) {
			c.mu.Lock()
			c.lastSeen = time.Now()
			c.mu.Unlock()
			st = knxnetip.StatusNoError
		}
		s.reply(p, m.Control, &knxnetip.ConnectionStateResponse{Channel: m.Channel, Status: st})
	case *knxnetip.DisconnectRequest:
		c := s.conn(m.Channel)
		if c == nil || !c.from(p) {
			s.reply(p, m.Control, &knxnetip.DisconnectResponse{Channel: m.Channel, Status: knxnetip.StatusConnectionID})
			return
		}
		// Remove the connection first: once the client has the response,
		// the channel is gone.
		s.disconnect(c, false, nil)
		s.reply(p, m.Control, &knxnetip.DisconnectResponse{Channel: m.Channel, Status: knxnetip.StatusNoError})
	case *knxnetip.DisconnectResponse:
		// The answer to our own DISCONNECT_REQUEST; the connection is gone.
	case *knxnetip.TunnellingRequest:
		if c := s.conn(m.Channel); c != nil && c.from(p) && c.kind != kindDevMgmt {
			c.onRequest(p, m)
		} else {
			s.o.metrics.OnDropped(net.UDPAddrFromAddrPort(from), "unknown_channel")
		}
	case *knxnetip.TunnellingAck:
		if c := s.conn(m.Channel); c != nil && c.from(p) {
			offerSeq(c.ackCh, ack{seq: m.Seq, status: m.Status})
		}
	case *knxnetip.DeviceConfigurationRequest:
		if c := s.conn(m.Channel); c != nil && c.from(p) && c.kind == kindDevMgmt {
			c.onDeviceConfiguration(p, m)
		} else {
			s.o.metrics.OnDropped(net.UDPAddrFromAddrPort(from), "unknown_channel")
		}
	case *knxnetip.DeviceConfigurationAck:
		if c := s.conn(m.Channel); c != nil && c.from(p) {
			offerSeq(c.ackCh, ack{seq: m.Seq, status: m.Status})
		}
	case *knxnetip.TunnellingFeature:
		if c := s.conn(m.Channel); c != nil && c.from(p) && c.kind != kindDevMgmt {
			c.onFeature(p, m)
		}
	case *knxnetip.RoutingIndication:
		if !s.o.routing || m.SystemBroadcast {
			return
		}
		f, err := cemi.Parse(m.CEMI)
		if err != nil {
			s.o.metrics.OnDecodeError(net.UDPAddrFromAddrPort(from), err)
			return
		}
		if ld, ok := f.(*cemi.LData); ok && ld.MsgCode == cemi.LDataInd {
			s.distribute(Telegram{Origin: FromRouting, Frame: ld}, nil)
		}
	case *knxnetip.RoutingBusy, *knxnetip.RoutingLostMessage:
		s.o.logger.Debugf("server: %s from %s", m.Service(), from)
	default:
		s.o.logger.Debugf("server: ignore %s from %s", m.Service(), from)
	}
}

// families returns the supported service families: core v2 (extended
// search, TCP) and tunnelling v2 (TCP, feature services) when TCP is on,
// v1 otherwise; device management v1.
func (s *Server) families() knxnetip.ServiceFamilies {
	v := uint8(1)
	if s.o.tcp {
		v = 2
	}
	f := knxnetip.ServiceFamilies{Families: []knxnetip.ServiceFamily{
		{ID: knxnetip.FamilyCore, Version: v},
		{ID: knxnetip.FamilyDeviceManagement, Version: 1},
		{ID: knxnetip.FamilyTunnelling, Version: v},
	}}
	if s.o.routing {
		f.Families = append(f.Families, knxnetip.ServiceFamily{ID: knxnetip.FamilyRouting, Version: 1})
	}
	if s.secured() {
		f.Families = append(f.Families, knxnetip.ServiceFamily{ID: knxnetip.FamilySecurity, Version: 1})
	}
	return f
}

// securedFamilies is the SECURED_SERVICE_FAMILIES DIB: the services that
// need KNX IP Secure.
func (s *Server) securedFamilies() knxnetip.ServiceFamilies {
	f := knxnetip.ServiceFamilies{Secured: true}
	if s.o.secure != nil {
		f.Families = append(f.Families, knxnetip.ServiceFamily{ID: knxnetip.FamilyDeviceManagement, Version: 1},
			knxnetip.ServiceFamily{ID: knxnetip.FamilyTunnelling, Version: 1})
	}
	if s.o.routing && s.o.secureRouting != nil {
		f.Families = append(f.Families, knxnetip.ServiceFamily{ID: knxnetip.FamilyRouting, Version: 1})
	}
	return f
}

// secured reports a server with any KNX IP Secure service.
func (s *Server) secured() bool {
	return s.o.secure != nil || (s.o.routing && s.o.secureRouting != nil)
}

func (s *Server) deviceInfo() knxnetip.DeviceInfo {
	d := knxnetip.DeviceInfo{Medium: knxnetip.MediumIP, Address: s.o.address, Serial: s.o.serial, MAC: s.o.mac, Name: s.friendlyName(), Multicast: netip.IPv4Unspecified()}
	if s.o.routing {
		d.Multicast = s.group.Addr()
	}
	if s.o.progMode {
		d.Status = 1
	}
	return d
}

// dibs returns the description blocks of types (nil: device info and
// supported services; extended adds the extended device info).
func (s *Server) dibs(types []knxnetip.DIBType, extended bool) knxnetip.DIBs {
	if types == nil {
		ds := knxnetip.DIBs{s.deviceInfo(), s.families()}
		if extended {
			ds = append(ds, knxnetip.ExtendedDeviceInfo{MaxAPDU: 254})
		}
		if s.secured() {
			ds = append(ds, s.securedFamilies())
		}
		return ds
	}
	var ds knxnetip.DIBs
	for _, t := range types {
		switch t {
		case knxnetip.DIBDeviceInfo:
			ds = append(ds, s.deviceInfo())
		case knxnetip.DIBSupportedServices:
			ds = append(ds, s.families())
		case knxnetip.DIBExtendedDeviceInfo:
			ds = append(ds, knxnetip.ExtendedDeviceInfo{MaxAPDU: 254})
		case knxnetip.DIBKNXAddresses:
			ds = append(ds, knxnetip.KNXAddresses{Addresses: append([]knx.IndividualAddress{s.o.address}, s.o.tunnels...)})
		case knxnetip.DIBTunnellingInfo:
			ds = append(ds, s.tunnellingInfo())
		case knxnetip.DIBSecuredServices:
			if s.secured() {
				ds = append(ds, s.securedFamilies())
			}
		default:
			// Not offered by this server: IP configuration, manufacturer
			// data.
		}
	}
	return ds
}

func (s *Server) tunnellingInfo() knxnetip.TunnellingInfo {
	s.mu.Lock()
	used := map[knx.IndividualAddress]bool{}
	for _, c := range s.conns {
		used[c.addr] = true
	}
	s.mu.Unlock()
	t := knxnetip.TunnellingInfo{MaxAPDU: 254}
	for _, a := range s.o.tunnels {
		st := uint16(0x04 | 0x02) // usable, authorised
		if !used[a] {
			st |= 0x01
		}
		t.Slots = append(t.Slots, knxnetip.TunnelSlot{Address: a, Status: st})
	}
	return t
}

// searchExt applies the search parameters of an extended search; ok is
// false when the server must not answer.
func (s *Server) searchExt(m *knxnetip.SearchRequestExt) (knxnetip.DIBs, bool) {
	var types []knxnetip.DIBType
	for _, p := range m.Params {
		switch p.Type {
		case knxnetip.SRPProgrammingMode:
			if !s.o.progMode {
				return nil, false
			}
		case knxnetip.SRPMACAddress:
			if len(p.Data) != 6 || [6]byte(p.Data) != s.o.mac {
				return nil, false
			}
		case knxnetip.SRPService:
			if len(p.Data) != 2 {
				return nil, false
			}
			v, ok := s.families().Version(knxnetip.ServiceFamilyID(p.Data[0]))
			if !ok || v < p.Data[1] {
				return nil, false
			}
		case knxnetip.SRPRequestDIBs:
			for _, t := range p.Data {
				if t != 0 {
					types = append(types, knxnetip.DIBType(t))
				}
			}
		default:
			if p.Mandatory {
				return nil, false
			}
		}
	}
	if types != nil {
		// The device information and supported families are always
		// included.
		ds := s.dibs([]knxnetip.DIBType{knxnetip.DIBDeviceInfo, knxnetip.DIBSupportedServices}, false)
		var rest []knxnetip.DIBType
		for _, t := range types {
			if t != knxnetip.DIBDeviceInfo && t != knxnetip.DIBSupportedServices {
				rest = append(rest, t)
			}
		}
		return append(ds, s.dibs(rest, false)...), true
	}
	return s.dibs(nil, true), true
}

func (s *Server) conn(ch uint8) *tconn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns[ch]
}

// maxDevMgmt bounds the device management connections.
const maxDevMgmt = 4

func (s *Server) onConnect(p peer, m *knxnetip.ConnectRequest) {
	from := p.addr
	ctrl := reply(m.Control, from)
	refuse := func(st knxnetip.Status) {
		s.reply(p, m.Control, &knxnetip.ConnectResponse{Status: st})
	}
	// UDP HPAIs over UDP, TCP HPAIs over TCP.
	want := knxnetip.IPv4UDP
	if p.tcp != nil {
		want, ctrl = knxnetip.IPv4TCP, p.addr
	}
	if m.Control.Protocol != want || m.Data.Protocol != want {
		refuse(knxnetip.StatusHostProtocolType)
		return
	}
	user, authed := p.secured()
	if s.o.secure != nil && !authed {
		refuse(knxnetip.StatusConnectionType)
		return
	}
	var kind connKind
	switch {
	case m.CRI.Type == knxnetip.DeviceManagementConnection:
		kind = kindDevMgmt
	case m.CRI.Type != knxnetip.TunnelConnection:
		refuse(knxnetip.StatusConnectionType)
		return
	case m.CRI.Layer == knxnetip.TunnelLinkLayer:
		kind = kindTunnel
	case m.CRI.Layer == knxnetip.TunnelBusmonitor:
		kind = kindBusmonitor
	default:
		refuse(knxnetip.StatusTunnellingLayer)
		return
	}
	if s.o.secure != nil && kind == kindDevMgmt && user != 1 {
		// Device management is for the management user (user 1), as
		// Calimero's secure server has it.
		refuse(knxnetip.StatusConnectionType)
		return
	}
	data := reply(m.Data, from)
	if p.tcp != nil {
		data = p.addr
	}
	dataHPAI := s.dataEndpoint(m, from)
	if p.tcp != nil {
		dataHPAI = knxnetip.TCPHPAI()
	}
	crd := func(c *tconn) knxnetip.CRD {
		if c.kind == kindDevMgmt {
			return knxnetip.CRD{Type: knxnetip.DeviceManagementConnection}
		}
		return knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: c.addr}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	// A repeated CONNECT_REQUEST of a client whose response was lost gets
	// its existing channel.
	for _, c := range s.conns {
		if c.kind == kind && c.ctrl == ctrl && c.data == data && c.tcp == p.tcp && c.us == p.us {
			s.mu.Unlock()
			s.reply(p, m.Control, &knxnetip.ConnectResponse{Channel: c.channel, Data: dataHPAI, CRD: crd(c)})
			return
		}
	}
	used := map[knx.IndividualAddress]bool{}
	devmgmt := 0
	for _, c := range s.conns {
		if c.kind == kindDevMgmt {
			devmgmt++
		} else {
			used[c.addr] = true
		}
	}
	// Busmonitor and link layer tunnelling exclude each other on a
	// subnetwork (as Calimero cites the standard), unless the server is a
	// simulator that monitors its own clients (WithConcurrentBusmonitor).
	if !s.o.concurrentBusmon {
		monitors, links := 0, 0
		for _, c := range s.conns {
			switch c.kind {
			case kindBusmonitor:
				monitors++
			case kindTunnel:
				links++
			case kindDevMgmt:
			}
		}
		if (kind == kindBusmonitor && links > 0) || (kind == kindTunnel && monitors > 0) {
			s.mu.Unlock()
			refuse(knxnetip.StatusNoMoreConnections)
			return
		}
	}
	var addr knx.IndividualAddress
	if kind == kindDevMgmt {
		if devmgmt >= maxDevMgmt {
			s.mu.Unlock()
			refuse(knxnetip.StatusNoMoreConnections)
			return
		}
	} else {
		found := false
		if bound := s.secureAddress(user, authed); bound != 0 {
			// A secure user tunnels with its own address.
			switch {
			case m.CRI.HasAddress && m.CRI.Address != bound:
				s.mu.Unlock()
				refuse(knxnetip.StatusAuthorisationError)
				return
			case used[bound]:
				s.mu.Unlock()
				refuse(knxnetip.StatusConnectionInUse)
				return
			}
			addr, found = bound, true
		} else if m.CRI.HasAddress {
			ours := false
			for _, a := range s.o.tunnels {
				ours = ours || a == m.CRI.Address
			}
			switch {
			case !ours:
				s.mu.Unlock()
				refuse(knxnetip.StatusNoTunnellingAddress)
				return
			case used[m.CRI.Address]:
				s.mu.Unlock()
				refuse(knxnetip.StatusConnectionInUse)
				return
			}
			addr, found = m.CRI.Address, true
		} else {
			for _, a := range s.o.tunnels {
				if !used[a] {
					addr, found = a, true
					break
				}
			}
		}
		if !found {
			s.mu.Unlock()
			refuse(knxnetip.StatusNoMoreConnections)
			return
		}
	}
	ch := s.next
	for i := 0; i < 256; i++ {
		ch++
		if _, taken := s.conns[ch]; ch != 0 && !taken {
			break
		}
	}
	s.next = ch
	c := &tconn{s: s, kind: kind, channel: ch, addr: addr, ctrl: ctrl, data: data, tcp: p.tcp, us: p.us, lastSeen: time.Now(),
		queue: make(chan out, s.o.queueSize), ackCh: make(chan ack, 1), done: make(chan struct{})}
	s.conns[ch] = c
	s.mu.Unlock()

	s.reply(p, m.Control, &knxnetip.ConnectResponse{Channel: ch, Data: dataHPAI, CRD: crd(c)})
	s.o.metrics.OnConnect(net.UDPAddrFromAddrPort(ctrl), ch)
	transport := "udp"
	if p.tcp != nil {
		transport = "tcp"
	}
	s.o.logger.Infof("server: channel %d (%s, %s) connected from %s as %s", ch, kind, transport, ctrl, addr)
	s.wg.Add(1)
	go c.sender()
}

// secureAddress returns the tunnelling address bound to an
// authenticated secure user, 0 for none.
func (s *Server) secureAddress(user uint8, authed bool) knx.IndividualAddress {
	if s.o.secure == nil || !authed {
		return 0
	}
	return s.o.secure.users[user].Address
}

// disconnect removes a connection; notify sends DISCONNECT_REQUEST to the
// client.
func (s *Server) disconnect(c *tconn, notify bool, cause error) {
	s.mu.Lock()
	if s.conns[c.channel] != c {
		s.mu.Unlock()
		return
	}
	delete(s.conns, c.channel)
	s.mu.Unlock()
	c.closeOnce.Do(func() { close(c.done) })
	// Record the disconnection before telling the client, so that
	// metrics never lag behind what the client sees.
	s.o.metrics.OnDisconnect(net.UDPAddrFromAddrPort(c.ctrl), c.channel, cause)
	if notify {
		if c.tcp != nil {
			c.tcp.write(&knxnetip.DisconnectRequest{Channel: c.channel, Control: knxnetip.TCPHPAI()})
		} else {
			s.write(c.ctrl, &knxnetip.DisconnectRequest{Channel: c.channel, Control: s.endpoint(c.ctrl)})
		}
	}
	s.o.logger.Infof("server: channel %d disconnected (%v)", c.channel, cause)
}

// janitor closes connections without heartbeat.
func (s *Server) janitor() {
	defer s.wg.Done()
	tick := s.o.aliveTime / 10
	if tick > time.Second {
		tick = time.Second
	}
	if tick < time.Millisecond {
		tick = time.Millisecond // NewTicker panics on 0
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-s.closing:
			return
		case <-t.C:
		}
		s.mu.Lock()
		var stale []*tconn
		for _, c := range s.conns {
			c.mu.Lock()
			if time.Since(c.lastSeen) > s.o.aliveTime {
				stale = append(stale, c)
			}
			c.mu.Unlock()
		}
		s.mu.Unlock()
		for _, c := range stale {
			s.disconnect(c, true, fmt.Errorf("%w: no heartbeat for %v", knx.ErrConnectionLost, s.o.aliveTime))
		}
		s.expireSessions()
	}
}

// Send puts a telegram on the virtual network as the server: it reaches
// every tunnelling client, the devices and, with routing, the multicast
// group. A zero source is replaced by the server's address; the message
// code becomes L_Data.ind.
func (s *Server) Send(f *cemi.LData) error {
	if _, err := f.AppendTo(nil); err != nil {
		return err
	}
	f = f.Clone()
	f.MsgCode = cemi.LDataInd
	if f.Source == 0 {
		f.Source = s.o.address
	}
	s.distribute(Telegram{Origin: FromServer, Frame: f}, nil)
	return nil
}

// GroupWrite sends A_GroupValue_Write of v to g as the server.
func (s *Server) GroupWrite(g knx.GroupAddress, v apdu.GroupValue) error {
	tpdu, err := apdu.GroupValueWrite(v)
	if err != nil {
		return err
	}
	return s.Send(cemi.NewGroupFrame(cemi.LDataInd, s.o.address, g, knx.PriorityLow, tpdu))
}

// Transmit sets a device's group object to v and, if the object has the C
// and T flags, sends the A_GroupValue_Write as that device.
func (s *Server) Transmit(d *device.Device, o *device.GroupObject, v any) error {
	f, err := d.Transmit(o, v)
	if err != nil || f == nil {
		return err
	}
	s.distribute(Telegram{Origin: FromDevice, Frame: f}, nil)
	return nil
}

// distribute delivers a telegram to everyone but its origin connection.
func (s *Server) distribute(t Telegram, origin *tconn) {
	f := t.Frame
	s.mu.Lock()
	targets := make([]*tconn, 0, len(s.conns))
	for _, c := range s.conns {
		if c != origin {
			targets = append(targets, c)
		}
	}
	devices := append([]*device.Device(nil), s.devices...)
	taps := make([]func(Telegram), 0, len(s.taps))
	for _, tap := range s.taps {
		taps = append(taps, tap)
	}
	s.mu.Unlock()

	for _, tap := range taps {
		tap(t)
	}
	ind := f
	if f.MsgCode != cemi.LDataInd {
		ind = f.Clone()
		ind.MsgCode = cemi.LDataInd
	}
	b, err := cemi.Marshal(ind)
	if err != nil {
		return
	}
	var busmon []byte
	for _, c := range targets {
		switch c.kind {
		case kindTunnel:
			c.enqueue(out{cemi: b})
		case kindBusmonitor:
			if busmon == nil {
				busmon = s.busmonitorFrame(ind)
			}
			if busmon != nil {
				c.enqueue(out{cemi: busmon})
			}
		case kindDevMgmt:
			// Device management connections carry no telegrams.
		}
	}
	if s.o.routing && t.Origin != FromRouting && ind.HopCount() > 0 {
		if s.routing.Allow() {
			s.writeRouting(&knxnetip.RoutingIndication{CEMI: b})
		} else {
			s.o.metrics.OnDropped(net.UDPAddrFromAddrPort(s.group), "routing_rate")
		}
	}
	for _, d := range devices {
		for _, resp := range d.Handle(ind) {
			s.distribute(Telegram{Origin: FromDevice, Frame: resp}, nil)
		}
	}
	// Remote device management of the server's own device.
	for _, resp := range s.mgmt.Handle(ind) {
		s.distribute(Telegram{Origin: FromServer, Frame: resp}, nil)
	}
}

// friendlyName returns the server's friendly name.
func (s *Server) friendlyName() string {
	s.nameMu.Lock()
	defer s.nameMu.Unlock()
	return s.name
}
