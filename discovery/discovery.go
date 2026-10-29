// SPDX-License-Identifier: MIT

// Package discovery finds KNXnet/IP servers (SEARCH_REQUEST, multicast or
// directed unicast, standard or extended) and reads their self
// description (DESCRIPTION_REQUEST).
//
// Search sends one request (or a few, see WithRepeat) and collects the
// answers until the timeout: it is not a scanner. Multicast discovery
// needs a network that carries 224.0.23.12 between the client and the
// servers; many container, VPN and cloud networks do not, so a directed
// search (WithUnicast) or Describe of a known address is the fallback.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/mcast"
	"github.com/otfabric/go-knx/internal/udp"
	"github.com/otfabric/go-knx/knxnetip"
)

// DefaultTimeout is the default collection time of a search
// (SEARCH_TIMEOUT of the standard is 10 s; servers answer within a few
// hundred milliseconds on a LAN).
const DefaultTimeout = 3 * time.Second

// Option configures Search and Describe.
type Option func(*options) error

type options struct {
	iface    string
	local    string
	timeout  time.Duration
	extended bool
	params   []knxnetip.SearchParam
	unicast  string
	nat      bool
	repeat   int
	logger   knx.Logger
}

func defaults() options {
	return options{timeout: DefaultTimeout, repeat: 1, logger: knx.NopLogger()}
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: discovery: %s", knx.ErrInvalidOption, fmt.Sprintf(format, a...))
}

// WithInterface sends multicast searches on the named network interface
// and announces its address.
func WithInterface(name string) Option { return func(o *options) error { o.iface = name; return nil } }

// WithLocalAddr binds the socket to a local address.
func WithLocalAddr(addr string) Option { return func(o *options) error { o.local = addr; return nil } }

// WithTimeout sets how long answers are collected (Search) or awaited
// (Describe).
func WithTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return invalid("timeout %v", d)
		}
		o.timeout = d
		return nil
	}
}

// WithExtended sends SEARCH_REQUEST_EXTENDED (KNXnet/IP core v2) with
// the given search parameters. Servers that only know the core v1
// services do not answer it.
func WithExtended(params ...knxnetip.SearchParam) Option {
	return func(o *options) error { o.extended, o.params = true, params; return nil }
}

// WithUnicast sends the search to one server instead of the multicast
// group: a directed search, answered by servers that support it. Search
// then returns as soon as the server answered.
func WithUnicast(addr string) Option { return func(o *options) error { o.unicast = addr; return nil } }

// WithNAT announces the route back endpoint 0.0.0.0:0, for clients behind
// NAT (directed search and describe only).
func WithNAT(on bool) Option { return func(o *options) error { o.nat = on; return nil } }

// WithRepeat sends the search n times (1..3), one second apart, for lossy
// networks.
func WithRepeat(n int) Option {
	return func(o *options) error {
		if n < 1 || n > 3 {
			return invalid("repeat %d (1..3)", n)
		}
		o.repeat = n
		return nil
	}
}

// WithLogger sets the logger.
func WithLogger(l knx.Logger) Option {
	return func(o *options) error {
		if l != nil {
			o.logger = l
		}
		return nil
	}
}

// Result is one server found by Search.
type Result struct {
	// From is the source of the response datagram.
	From netip.AddrPort
	// Control is the control endpoint the server announced.
	Control knxnetip.HPAI
	// Extended is set for a SEARCH_RESPONSE_EXTENDED.
	Extended bool
	DIBs     knxnetip.DIBs
}

// Device returns the DEVICE_INFO block.
func (r Result) Device() knxnetip.DeviceInfo { d, _ := r.DIBs.DeviceInfo(); return d }

// Services returns the supported service families.
func (r Result) Services() knxnetip.ServiceFamilies { s, _ := r.DIBs.SupportedServices(); return s }

// Endpoint returns the address to connect to: the announced control
// endpoint, or the source of the response when the server announced the
// route back endpoint.
func (r Result) Endpoint() netip.AddrPort {
	if r.Control.IsRouteBack() {
		return r.From
	}
	return r.Control.Addr
}

type socket struct {
	conn *net.UDPConn
	hpai knxnetip.HPAI
}

func open(ctx context.Context, o options, remote netip.AddrPort) (*socket, error) {
	local := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	var err error
	var ifIP netip.Addr
	if o.iface != "" {
		if _, ifIP, err = udp.InterfaceIPv4(o.iface); err != nil {
			return nil, err
		}
		local = netip.AddrPortFrom(ifIP, 0)
	}
	if o.local != "" {
		if local, err = udp.ResolveEndpoint(ctx, o.local, 0); err != nil {
			return nil, err
		}
	}
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, fmt.Errorf("discovery: listen %s: %w", local, err)
	}
	s := &socket{conn: c}
	bound := udp.AddrPortOf(c.LocalAddr())
	ip := bound.Addr()
	if !ip.IsValid() || ip.IsUnspecified() {
		if ifIP.IsValid() {
			ip = ifIP
		} else if ip, err = udp.LocalIPFor(remote); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("discovery: no route to %s: %w", remote, err)
		}
	}
	if remote.Addr().IsMulticast() {
		if err := mcast.Configure(c, &ip, true, 1); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	if o.nat {
		s.hpai = knxnetip.RouteBackHPAI()
	} else {
		s.hpai = knxnetip.NewHPAI(netip.AddrPortFrom(ip, bound.Port()))
	}
	return s, nil
}

// Search sends a search request and returns the servers that answered
// within the timeout, ordered by endpoint. It returns an empty slice,
// not an error, when none answered.
func Search(ctx context.Context, opts ...Option) ([]Result, error) {
	o := defaults()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	remote := netip.AddrPortFrom(knxnetip.MulticastAddress, knxnetip.Port)
	if o.unicast != "" {
		var err error
		if remote, err = udp.ResolveEndpoint(ctx, o.unicast, knxnetip.Port); err != nil {
			return nil, err
		}
	} else if o.nat {
		return nil, invalid("NAT applies to directed search only")
	}
	s, err := open(ctx, o, remote)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.conn.Close() }()

	var req knxnetip.Message = &knxnetip.SearchRequest{Discovery: s.hpai}
	if o.extended {
		req = &knxnetip.SearchRequestExt{Discovery: s.hpai, Params: o.params}
	}
	b, err := knxnetip.Marshal(req)
	if err != nil {
		return nil, err
	}
	// ctx ends the search through AfterFunc below, so that its expiry
	// always reports ctx.Err().
	deadline := time.Now().Add(o.timeout)
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetReadDeadline(time.Now()) })
	defer stop()

	sent := 0
	send := func() error {
		sent++
		_, err := s.conn.WriteToUDPAddrPort(b, remote)
		return err
	}
	if err := send(); err != nil {
		return nil, fmt.Errorf("discovery: send search to %s: %w", remote, err)
	}
	nextSend := time.Now().Add(time.Second)

	seen := map[string]bool{}
	var results []Result
	buf := make([]byte, knxnetip.MaxFrameLen+1)
	for {
		until := deadline
		if sent < o.repeat && nextSend.Before(until) {
			until = nextSend
		}
		_ = s.conn.SetReadDeadline(until)
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if ctx.Err() != nil {
					return results, ctx.Err()
				}
				if time.Now().Before(deadline) && sent < o.repeat {
					_ = send()
					nextSend = time.Now().Add(time.Second)
					continue
				}
				break
			}
			return results, err
		}
		m, err := knxnetip.Parse(buf[:n])
		if err != nil {
			o.logger.Debugf("discovery: drop datagram from %s: %v", from, err)
			continue
		}
		resp, ok := m.(*knxnetip.SearchResponse)
		if !ok {
			continue
		}
		r := Result{From: netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), Control: resp.Control, Extended: resp.Extended, DIBs: resp.DIBs}
		d, _ := r.DIBs.DeviceInfo()
		key := r.Endpoint().String() + "/" + d.SerialString()
		if seen[key] {
			continue
		}
		seen[key] = true
		results = append(results, r)
		if o.unicast != "" {
			break // a directed search has one answer
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Endpoint().Compare(results[j].Endpoint()) < 0 })
	if results == nil {
		results = []Result{}
	}
	return results, nil
}

// Describe sends a DESCRIPTION_REQUEST to the server at addr and returns
// the DIBs of its response. The request is sent up to three times within
// the timeout.
func Describe(ctx context.Context, addr string, opts ...Option) (knxnetip.DIBs, error) {
	o := defaults()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	remote, err := udp.ResolveEndpoint(ctx, addr, knxnetip.Port)
	if err != nil {
		return nil, err
	}
	s, err := open(ctx, o, remote)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.conn.Close() }()
	b, err := knxnetip.Marshal(&knxnetip.DescriptionRequest{Control: s.hpai})
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.conn.SetReadDeadline(time.Now()) })
	defer stop()
	buf := make([]byte, knxnetip.MaxFrameLen+1)
	step := o.timeout / 3
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := s.conn.WriteToUDPAddrPort(b, remote); err != nil {
			return nil, fmt.Errorf("discovery: send description request to %s: %w", remote, err)
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(step))
		for {
			n, from, err := s.conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				return nil, err
			}
			if from.Addr().Unmap() != remote.Addr() {
				continue
			}
			m, err := knxnetip.Parse(buf[:n])
			if err != nil {
				o.logger.Debugf("discovery: drop datagram from %s: %v", from, err)
				continue
			}
			if r, ok := m.(*knxnetip.DescriptionResponse); ok {
				return r.DIBs, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: discovery: no DESCRIPTION_RESPONSE from %s within %v", knx.ErrTimeout, remote, o.timeout)
}
