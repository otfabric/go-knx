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
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/internal/mcast"
	"github.com/otfabric/go-knx/internal/ratelimit"
	"github.com/otfabric/go-knx/internal/udp"
	"github.com/otfabric/go-knx/knxnetip"
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

	mu      sync.Mutex
	conns   map[uint8]*tconn
	next    uint8
	devices []*device.Device
	taps    map[int]func(Telegram)
	tapID   int
	started bool
	closed  bool

	closing chan struct{}
	wg      sync.WaitGroup
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
	return &Server{o: o, conns: map[uint8]*tconn{}, taps: map[int]func(Telegram){}, closing: make(chan struct{}), routing: ratelimit.New(o.routingRate)}, nil
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
	if sameSocket {
		join := s.group
		if !s.o.routing {
			join = discGroup
		}
		if s.main, err = mcast.Listen(ifi, join, false, s.o.ttl); err != nil {
			return fmt.Errorf("server: %w", err)
		}
		if s.ifIP.IsValid() {
			ip := s.ifIP
			_ = mcast.Configure(s.main, &ip, false, s.o.ttl)
		}
	} else {
		if s.main, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listen)); err != nil {
			return fmt.Errorf("server: listen %s: %w", listen, err)
		}
		if s.o.routing {
			s.main.Close()
			return invalid("routing needs the listen port to be the multicast group's port %d", s.group.Port())
		}
		if s.o.discovery {
			if s.disc, err = mcast.Listen(ifi, discGroup, false, 1); err != nil {
				s.o.logger.Warnf("server: discovery disabled: %v", err)
				s.disc = nil
			}
		}
	}
	s.o.logger.Infof("server: listening on %s (discovery %t, routing %t)", s.main.LocalAddr(), s.o.discovery, s.o.routing)
	s.wg.Add(2)
	go s.readLoop(s.main)
	go s.janitor()
	if s.disc != nil {
		s.wg.Add(1)
		go s.readLoop(s.disc)
	}
	return nil
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
	if s.main == nil {
		return netip.AddrPort{}
	}
	return udp.AddrPortOf(s.main.LocalAddr())
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
	s.mu.Unlock()
	for _, c := range conns {
		s.disconnect(c, true, nil)
	}
	close(s.closing)
	if s.main != nil {
		s.main.Close()
	}
	if s.disc != nil {
		s.disc.Close()
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
	if _, err := s.main.WriteToUDPAddrPort(b, to); err != nil {
		s.o.logger.Debugf("server: write %s to %s: %v", m.Service(), to, err)
		return
	}
	s.o.metrics.OnFrameSent(net.UDPAddrFromAddrPort(to), uint16(m.Service()), len(b))
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
		s.handle(from, m)
	}
}

func reply(h knxnetip.HPAI, from netip.AddrPort) netip.AddrPort {
	if h.IsRouteBack() {
		return from
	}
	return h.Addr
}

func (s *Server) handle(from netip.AddrPort, m knxnetip.Message) {
	switch m := m.(type) {
	case *knxnetip.SearchRequest:
		if m.Discovery.Protocol != knxnetip.IPv4UDP {
			return
		}
		s.write(reply(m.Discovery, from), &knxnetip.SearchResponse{Control: s.endpoint(from), DIBs: s.dibs(nil, false)})
	case *knxnetip.SearchRequestExt:
		if m.Discovery.Protocol != knxnetip.IPv4UDP {
			return
		}
		if dibs, ok := s.searchExt(m); ok {
			s.write(reply(m.Discovery, from), &knxnetip.SearchResponse{Extended: true, Control: s.endpoint(from), DIBs: dibs})
		}
	case *knxnetip.DescriptionRequest:
		s.write(reply(m.Control, from), &knxnetip.DescriptionResponse{DIBs: s.dibs(nil, false)})
	case *knxnetip.ConnectRequest:
		s.onConnect(from, m)
	case *knxnetip.ConnectionStateRequest:
		st := knxnetip.StatusConnectionID
		if c := s.conn(m.Channel); c != nil && c.from(from) {
			c.mu.Lock()
			c.lastSeen = time.Now()
			c.mu.Unlock()
			st = knxnetip.StatusNoError
		}
		s.write(reply(m.Control, from), &knxnetip.ConnectionStateResponse{Channel: m.Channel, Status: st})
	case *knxnetip.DisconnectRequest:
		c := s.conn(m.Channel)
		if c == nil || !c.from(from) {
			s.write(reply(m.Control, from), &knxnetip.DisconnectResponse{Channel: m.Channel, Status: knxnetip.StatusConnectionID})
			return
		}
		s.write(reply(m.Control, from), &knxnetip.DisconnectResponse{Channel: m.Channel, Status: knxnetip.StatusNoError})
		s.disconnect(c, false, nil)
	case *knxnetip.DisconnectResponse:
		// The answer to our own DISCONNECT_REQUEST; the connection is gone.
	case *knxnetip.TunnellingRequest:
		if c := s.conn(m.Channel); c != nil && c.from(from) {
			c.onRequest(from, m)
		} else {
			s.o.metrics.OnDropped(net.UDPAddrFromAddrPort(from), "unknown_channel")
		}
	case *knxnetip.TunnellingAck:
		if c := s.conn(m.Channel); c != nil && c.from(from) {
			offerSeq(c.ackCh, ack{seq: m.Seq, status: m.Status})
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

// families returns the supported service families. Core v1: TCP and the
// v2 tunnelling features are not implemented (extended search is
// answered nevertheless).
func (s *Server) families() knxnetip.ServiceFamilies {
	f := knxnetip.ServiceFamilies{Families: []knxnetip.ServiceFamily{
		{ID: knxnetip.FamilyCore, Version: 1},
		{ID: knxnetip.FamilyTunnelling, Version: 1},
	}}
	if s.o.routing {
		f.Families = append(f.Families, knxnetip.ServiceFamily{ID: knxnetip.FamilyRouting, Version: 1})
	}
	return f
}

func (s *Server) deviceInfo() knxnetip.DeviceInfo {
	d := knxnetip.DeviceInfo{Medium: knxnetip.MediumIP, Address: s.o.address, Serial: s.o.serial, MAC: s.o.mac, Name: s.o.name, Multicast: netip.IPv4Unspecified()}
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

func (s *Server) onConnect(from netip.AddrPort, m *knxnetip.ConnectRequest) {
	ctrl := reply(m.Control, from)
	refuse := func(st knxnetip.Status) {
		s.write(ctrl, &knxnetip.ConnectResponse{Status: st})
	}
	if m.Control.Protocol != knxnetip.IPv4UDP || m.Data.Protocol != knxnetip.IPv4UDP {
		refuse(knxnetip.StatusHostProtocolType)
		return
	}
	if m.CRI.Type != knxnetip.TunnelConnection {
		refuse(knxnetip.StatusConnectionType)
		return
	}
	if m.CRI.Layer != knxnetip.TunnelLinkLayer {
		refuse(knxnetip.StatusTunnellingLayer)
		return
	}
	data := reply(m.Data, from)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	// A repeated CONNECT_REQUEST of a client whose response was lost gets
	// its existing channel.
	for _, c := range s.conns {
		if c.ctrl == ctrl && c.data == data {
			s.mu.Unlock()
			s.write(ctrl, &knxnetip.ConnectResponse{Channel: c.channel, Data: s.endpoint(from), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: c.addr}})
			return
		}
	}
	used := map[knx.IndividualAddress]bool{}
	for _, c := range s.conns {
		used[c.addr] = true
	}
	var addr knx.IndividualAddress
	found := false
	if m.CRI.HasAddress {
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
	ch := s.next
	for i := 0; i < 256; i++ {
		ch++
		if _, taken := s.conns[ch]; ch != 0 && !taken {
			break
		}
	}
	s.next = ch
	c := &tconn{s: s, channel: ch, addr: addr, ctrl: ctrl, data: data, lastSeen: time.Now(),
		queue: make(chan []byte, s.o.queueSize), ackCh: make(chan ack, 1), done: make(chan struct{})}
	s.conns[ch] = c
	s.mu.Unlock()

	s.write(ctrl, &knxnetip.ConnectResponse{Channel: ch, Data: s.endpoint(from), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: addr}})
	s.o.metrics.OnConnect(net.UDPAddrFromAddrPort(ctrl), ch)
	s.o.logger.Infof("server: channel %d connected from %s as %s", ch, ctrl, addr)
	s.wg.Add(1)
	go c.sender()
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
	if notify {
		s.write(c.ctrl, &knxnetip.DisconnectRequest{Channel: c.channel, Control: s.endpoint(c.ctrl)})
	}
	s.o.metrics.OnDisconnect(net.UDPAddrFromAddrPort(c.ctrl), c.channel, cause)
	s.o.logger.Infof("server: channel %d disconnected (%v)", c.channel, cause)
}

// janitor closes connections without heartbeat.
func (s *Server) janitor() {
	defer s.wg.Done()
	tick := s.o.aliveTime / 10
	if tick > time.Second {
		tick = time.Second
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
	for _, c := range targets {
		c.enqueue(b)
	}
	if s.o.routing && t.Origin != FromRouting && ind.HopCount() > 0 {
		if s.routing.Allow() {
			s.write(s.group, &knxnetip.RoutingIndication{CEMI: b})
		} else {
			s.o.metrics.OnDropped(net.UDPAddrFromAddrPort(s.group), "routing_rate")
		}
	}
	for _, d := range devices {
		for _, resp := range d.Handle(ind) {
			s.distribute(Telegram{Origin: FromDevice, Frame: resp}, nil)
		}
	}
}
