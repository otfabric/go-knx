// SPDX-License-Identifier: MIT

// Package routing sends and receives KNX telegrams with KNXnet/IP routing:
// ROUTING_INDICATIONs on an IP multicast group (224.0.23.12:3671 by
// default), with flow control.
//
// Safety: a Conn never forwards what it receives; it only sends what the
// application gives it. Outgoing indications are rate limited (default 50
// per second) and paused for the wait time of a ROUTING_BUSY. Telegrams
// with hop count 0 are not sent. With multicast loopback enabled, the
// Conn's own indications are recognised and not delivered back.
package routing

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/mcast"
	"github.com/otfabric/go-knx/internal/ratelimit"
	"github.com/otfabric/go-knx/internal/udp"
	"github.com/otfabric/go-knx/knxnetip"
)

// Defaults.
const (
	DefaultRate      = 50
	DefaultQueueSize = 256
	DefaultTTL       = 16
)

// Option configures a [Conn].
type Option func(*options) error

type options struct {
	iface     string
	group     string
	rate      int
	queueSize int
	loopback  bool
	ttl       int
	logger    knx.Logger
	metrics   knx.Metrics
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: routing: %s", knx.ErrInvalidOption, fmt.Sprintf(format, a...))
}

// WithInterface joins the group and sends on the named interface.
func WithInterface(name string) Option { return func(o *options) error { o.iface = name; return nil } }

// WithGroup sets the multicast group (default 224.0.23.12:3671).
func WithGroup(addr string) Option { return func(o *options) error { o.group = addr; return nil } }

// WithRate bounds the indications sent per second (default 50; 0: no
// limit). Sends over the limit wait.
func WithRate(n int) Option {
	return func(o *options) error {
		if n < 0 {
			return invalid("rate %d", n)
		}
		o.rate = n
		return nil
	}
}

// WithQueueSize bounds the inbound queue (default 256).
func WithQueueSize(n int) Option {
	return func(o *options) error {
		if n < 1 || n > 1<<16 {
			return invalid("queue size %d", n)
		}
		o.queueSize = n
		return nil
	}
}

// WithLoopback enables multicast loopback, so that routers on the same
// host hear each other (default off). The Conn drops its own echoes.
func WithLoopback(on bool) Option { return func(o *options) error { o.loopback = on; return nil } }

// WithTTL sets the multicast TTL (default 16).
func WithTTL(ttl int) Option {
	return func(o *options) error {
		if ttl < 1 || ttl > 255 {
			return invalid("TTL %d", ttl)
		}
		o.ttl = ttl
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

// WithMetrics sets the metrics callbacks.
func WithMetrics(m knx.Metrics) Option {
	return func(o *options) error {
		if m != nil {
			o.metrics = m
		}
		return nil
	}
}

// Event is something other than a telegram seen on the group.
type Event struct {
	From netip.AddrPort
	// Busy is set for ROUTING_BUSY, Lost for ROUTING_LOST_MESSAGE.
	Busy *knxnetip.RoutingBusy
	Lost *knxnetip.RoutingLostMessage
}

// Conn is a routing endpoint.
type Conn struct {
	o     options
	sock  *net.UDPConn
	group netip.AddrPort
	rate  *ratelimit.Bucket

	sendMu    sync.Mutex
	mu        sync.Mutex
	busyUntil time.Time
	echoes    map[[32]byte]time.Time

	inbound chan cemi.Frame
	events  chan Event
	closing chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

// Listen joins the routing multicast group.
func Listen(ctx context.Context, opts ...Option) (*Conn, error) {
	o := options{group: "224.0.23.12:3671", rate: DefaultRate, queueSize: DefaultQueueSize, ttl: DefaultTTL, logger: knx.NopLogger(), metrics: knx.NopMetrics{}}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	group, err := udp.ResolveEndpoint(ctx, o.group, knxnetip.Port)
	if err != nil {
		return nil, err
	}
	if !group.Addr().IsMulticast() {
		return nil, invalid("%s is not a multicast group", group)
	}
	var ifi *net.Interface
	var ifIP netip.Addr
	if o.iface != "" {
		if ifi, ifIP, err = udp.InterfaceIPv4(o.iface); err != nil {
			return nil, err
		}
	}
	sock, err := mcast.Listen(ifi, group, o.loopback, o.ttl)
	if err != nil {
		return nil, fmt.Errorf("routing: %w", err)
	}
	if ifIP.IsValid() {
		_ = mcast.Configure(sock, &ifIP, o.loopback, o.ttl)
	}
	c := &Conn{o: o, sock: sock, group: group, rate: ratelimit.New(o.rate), echoes: map[[32]byte]time.Time{},
		inbound: make(chan cemi.Frame, o.queueSize), events: make(chan Event, 16), closing: make(chan struct{})}
	c.wg.Add(1)
	go c.readLoop()
	return c, nil
}

// Group returns the multicast group.
func (c *Conn) Group() netip.AddrPort { return c.group }

// Send sends a cEMI frame (an L_Data.ind) as a ROUTING_INDICATION. It
// waits for the rate limit and for a pending ROUTING_BUSY wait time, and
// refuses frames with hop count 0.
func (c *Conn) Send(ctx context.Context, f cemi.Frame) error {
	if ld, ok := f.(*cemi.LData); ok {
		if ld.HopCount() == 0 {
			return fmt.Errorf("%w: routing: hop count 0 is not routed", knx.ErrInvalidValue)
		}
		if ld.MsgCode != cemi.LDataInd {
			ld = ld.Clone()
			ld.MsgCode = cemi.LDataInd
			f = ld
		}
	}
	b, err := cemi.Marshal(f)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	for !c.rate.Allow() {
		if err := sleep(ctx, c.closing, 5*time.Millisecond); err != nil {
			return err
		}
	}
	c.mu.Lock()
	wait := time.Until(c.busyUntil)
	c.mu.Unlock()
	if wait > 0 {
		if err := sleep(ctx, c.closing, wait); err != nil {
			return err
		}
	}
	frame, err := knxnetip.Marshal(&knxnetip.RoutingIndication{CEMI: b})
	if err != nil {
		return err
	}
	if c.o.loopback {
		c.mu.Lock()
		now := time.Now()
		for k, t := range c.echoes {
			if now.Sub(t) > 2*time.Second {
				delete(c.echoes, k)
			}
		}
		if len(c.echoes) < 1024 {
			c.echoes[sha256.Sum256(frame)] = now
		}
		c.mu.Unlock()
	}
	if _, err := c.sock.WriteToUDPAddrPort(frame, c.group); err != nil {
		return fmt.Errorf("routing: send: %w", err)
	}
	c.o.metrics.OnFrameSent(net.UDPAddrFromAddrPort(c.group), uint16(knxnetip.RoutingIndicationType), len(frame))
	return nil
}

func sleep(ctx context.Context, closing chan struct{}, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-closing:
		return knx.ErrClosed
	}
}

// Receive returns the next frame of a ROUTING_INDICATION from another
// router.
func (c *Conn) Receive(ctx context.Context) (cemi.Frame, error) {
	select {
	case f := <-c.inbound:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closing:
		return nil, knx.ErrClosed
	}
}

// Events returns ROUTING_BUSY and ROUTING_LOST_MESSAGE notifications
// (bounded; older ones are dropped when not read).
func (c *Conn) Events() <-chan Event { return c.events }

func (c *Conn) readLoop() {
	defer c.wg.Done()
	buf := make([]byte, knxnetip.MaxFrameLen+1)
	for {
		n, from, err := c.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		fa := net.UDPAddrFromAddrPort(from)
		if c.o.loopback {
			h := sha256.Sum256(buf[:n])
			c.mu.Lock()
			_, own := c.echoes[h]
			delete(c.echoes, h)
			c.mu.Unlock()
			if own {
				continue
			}
		}
		m, err := knxnetip.Parse(buf[:n])
		if err != nil {
			c.o.metrics.OnDecodeError(fa, err)
			continue
		}
		c.o.metrics.OnFrameReceived(fa, uint16(m.Service()), n)
		switch m := m.(type) {
		case *knxnetip.RoutingIndication:
			if m.SystemBroadcast {
				continue
			}
			f, err := cemi.Parse(m.CEMI)
			if err != nil {
				c.o.metrics.OnDecodeError(fa, err)
				continue
			}
			select {
			case c.inbound <- f:
			default:
				c.o.metrics.OnDropped(fa, "queue_full")
			}
		case *knxnetip.RoutingBusy:
			c.mu.Lock()
			if until := time.Now().Add(time.Duration(m.WaitTime) * time.Millisecond); until.After(c.busyUntil) {
				c.busyUntil = until
			}
			c.mu.Unlock()
			c.event(Event{From: from, Busy: m})
		case *knxnetip.RoutingLostMessage:
			c.event(Event{From: from, Lost: m})
		}
	}
}

func (c *Conn) event(e Event) {
	select {
	case c.events <- e:
	default:
	}
}

// Close leaves the group and stops the reader.
func (c *Conn) Close() error {
	c.once.Do(func() {
		close(c.closing)
		_ = c.sock.Close()
		c.wg.Wait()
	})
	return nil
}
