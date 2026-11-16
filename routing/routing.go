// SPDX-License-Identifier: MIT

// Package routing sends and receives KNX telegrams with KNXnet/IP routing:
// ROUTING_INDICATIONs on an IP multicast group (224.0.23.12:3671 by
// default), with flow control.
//
// Safety: a Conn never forwards what it receives; it only sends what the
// application gives it. Outgoing indications are paced (at most one per
// 1/rate, default 50 per second, no bursts) and follow the flow control
// of KNXnet/IP routing on ROUTING_BUSY: a pause of the frame's wait time
// plus a random extension that grows with the number of busy frames,
// then a reduced rate until that number has decayed. Telegrams
// with hop count 0 are not sent. With multicast loopback enabled, the
// Conn's own indications are recognised and not delivered back.
//
// With [WithSecure] the Conn speaks KNX IP Secure routing: every frame is
// sent and received in a SECURE_WRAPPER under the backbone key, with the
// synchronised multicast timer as sequence (package secure).
package routing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/backoff"
	"github.com/otfabric/go-knx/internal/flowctl"
	"github.com/otfabric/go-knx/internal/mcast"
	"github.com/otfabric/go-knx/internal/udp"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
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
	address   knx.IndividualAddress
	iface     string
	group     string
	rate      int
	maxPause  time.Duration
	maxCount  int
	queueSize int
	loopback  bool
	ttl       int
	logger    knx.Logger
	metrics   knx.Metrics
	secure    *secureOptions
	serial    [6]byte
}

type secureOptions struct {
	key     secure.Key
	latency time.Duration
}

// WithSecure enables KNX IP Secure routing with the backbone key and the
// latency tolerance of the backbone (0: secure.DefaultLatency). Listen
// then synchronises the multicast timer: it collects the answers of the
// other secure routers for the whole synchronisation window (about 3.3 s
// at the default latency) and uses the newest timer value. The window is
// not shortened: a context that ends inside it makes Listen fail with
// the context's error.
func WithSecure(key secure.Key, latency time.Duration) Option {
	return func(o *options) error {
		if latency < 0 {
			return invalid("latency %v", latency)
		}
		o.secure = &secureOptions{key: key, latency: latency}
		return nil
	}
}

// WithSerialNumber sets the KNX serial number sent in secure frames
// (default 00FA followed by four random octets).
func WithSerialNumber(s [6]byte) Option { return func(o *options) error { o.serial = s; return nil } }

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: routing: %s", knx.ErrInvalidOption, fmt.Sprintf(format, a...))
}

// DefaultIndividualAddress is the source address a Conn puts in
// telegrams sent with source 0.0.0: 15.15.255, the address of an
// unconfigured device. Routers drop telegrams from 0.0.0.
var DefaultIndividualAddress = knx.MustParseIndividualAddress("15.15.255")

// WithIndividualAddress sets the source address put in telegrams sent
// with source 0.0.0 (default 15.15.255).
func WithIndividualAddress(a knx.IndividualAddress) Option {
	return func(o *options) error {
		if a == 0 {
			return invalid("individual address 0.0.0")
		}
		o.address = a
		return nil
	}
}

// WithInterface joins the group and sends on the named interface.
func WithInterface(name string) Option { return func(o *options) error { o.iface = name; return nil } }

// WithGroup sets the multicast group (default 224.0.23.12:3671).
func WithGroup(addr string) Option { return func(o *options) error { o.group = addr; return nil } }

// WithRate bounds the indications sent per second (default 50; 0: no
// limit): consecutive indications are at least 1/n apart, and sends wait
// for their turn. ROUTING_BUSY is honoured at any rate.
func WithRate(n int) Option {
	return func(o *options) error {
		if n < 0 {
			return invalid("rate %d", n)
		}
		o.rate = n
		return nil
	}
}

// WithMaxBusyPause bounds the pause after a ROUTING_BUSY, the frame's
// wait time and the random extension together, to d, measured from the
// busy frame that starts or extends the pause. 0, the default, leaves the
// pause to the frame: up to 65.535 s plus the extension. The reduced rate
// after the pause is not changed. A negative d is knx.ErrInvalidOption.
func WithMaxBusyPause(d time.Duration) Option {
	return func(o *options) error {
		if d < 0 {
			return invalid("max busy pause %v", d)
		}
		o.maxPause = d
		return nil
	}
}

// WithMaxBusyCount bounds the busy counter of the flow control to n. Each
// ROUTING_BUSY that arrives more than 10 ms after the previous one raises
// the counter by one, and it sets the random extension of the pause (up
// to the counter × 50 ms), how long the reduced rate lasts after the
// pause (the counter × 100 ms) and how reduced it is (a gap of the
// counter + 1 times the normal one). 0, the default, leaves the counter
// unbounded. A negative n is knx.ErrInvalidOption.
func WithMaxBusyCount(n int) Option {
	return func(o *options) error {
		if n < 0 {
			return invalid("max busy count %d", n)
		}
		o.maxCount = n
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
	flow  *flowctl.Controller

	// turn is the send turn: Send holds it while it waits for the flow
	// control and transmits. A Send that waits for the turn leaves when
	// its context ends or the Conn closes.
	turn   chan struct{}
	mu     sync.Mutex
	echoes map[[32]byte]time.Time
	timer  *secure.RoutingTimer

	inbound chan cemi.Frame
	events  chan Event
	closing chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

// Listen joins the routing multicast group. With [WithSecure] it returns
// after the timer synchronisation; when ctx ends before that, it closes
// the socket and returns an error matching ctx.Err(). An error of an
// expired deadline matches knx.ErrTimeout too.
func Listen(ctx context.Context, opts ...Option) (*Conn, error) {
	c, err := listen(ctx, opts...)
	if err != nil {
		return nil, deadline(err)
	}
	return c, nil
}

// listen is Listen; Listen makes the error of an expired deadline match
// knx.ErrTimeout too.
func listen(ctx context.Context, opts ...Option) (*Conn, error) {
	o := options{address: DefaultIndividualAddress, group: "224.0.23.12:3671", rate: DefaultRate, queueSize: DefaultQueueSize, ttl: DefaultTTL, logger: knx.NopLogger(), metrics: knx.NopMetrics{}}
	o.serial[0], o.serial[1] = 0x00, 0xFA
	_, _ = rand.Read(o.serial[2:])
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
	c := &Conn{o: o, sock: sock, group: group, flow: flowctl.New(o.rate), echoes: map[[32]byte]time.Time{}, turn: make(chan struct{}, 1),
		inbound: make(chan cemi.Frame, o.queueSize), events: make(chan Event, 16), closing: make(chan struct{})}
	c.flow.SetMaxPause(o.maxPause)
	c.flow.SetMaxCount(o.maxCount)
	if o.secure != nil {
		c.timer = secure.NewRoutingTimer(o.secure.key, o.serial, o.secure.latency, c.sendNotify)
	}
	c.wg.Add(1)
	go c.readLoop(sock.ReadFromUDPAddrPort)
	if c.timer != nil {
		c.timer.Synchronize(ctx)
		if !c.timer.Authenticated() {
			// ctx ended inside the synchronisation window: without a
			// synchronised timer the Conn accepts and sends nothing.
			_ = c.Close()
			return nil, fmt.Errorf("routing: timer synchronisation: %w", ctx.Err())
		}
	}
	return c, nil
}

// sendNotify sends a TIMER_NOTIFY of the routing timer.
func (c *Conn) sendNotify(m *knxnetip.TimerNotify) {
	b, err := knxnetip.Marshal(m)
	if err != nil {
		return
	}
	if err := c.transmit(context.Background(), b, knxnetip.TimerNotifyType); err != nil {
		c.o.logger.Debugf("routing: timer notify: %v", err)
	}
}

// IndividualAddress returns the source address of telegrams sent with
// source 0.0.0.
func (c *Conn) IndividualAddress() knx.IndividualAddress { return c.o.address }

// Group returns the multicast group.
func (c *Conn) Group() netip.AddrPort { return c.group }

// Send sends a cEMI frame (an L_Data.ind) as a ROUTING_INDICATION; a
// source of 0.0.0 is replaced by the Conn's individual address. It
// waits for the pause after the previous indication and for the flow
// control of a ROUTING_BUSY, and refuses frames with hop count 0.
//
// Sends take turns. Every wait of Send ends when ctx ends (with ctx's
// error) or the Conn closes (knx.ErrClosed): the wait for the turn while
// another Send waits for the flow control, and the wait for the flow
// control itself. A Send whose context deadline passes, in a wait or
// during the write, returns an error matching knx.ErrTimeout and
// context.DeadlineExceeded. After Close, Send returns knx.ErrClosed and
// sends nothing.
func (c *Conn) Send(ctx context.Context, f cemi.Frame) error {
	return deadline(c.send(ctx, f))
}

// send is Send; Send makes the error of an expired deadline match
// knx.ErrTimeout too.
func (c *Conn) send(ctx context.Context, f cemi.Frame) error {
	if c.closed() {
		return errClosed
	}
	if ld, ok := f.(*cemi.LData); ok {
		if ld.HopCount() == 0 {
			return fmt.Errorf("%w: routing: hop count 0 is not routed", knx.ErrInvalidValue)
		}
		if ld.MsgCode != cemi.LDataInd || ld.Source == 0 {
			ld = ld.Clone()
			ld.MsgCode = cemi.LDataInd
			if ld.Source == 0 {
				ld.Source = c.o.address
			}
			f = ld
		}
	}
	b, err := cemi.Marshal(f)
	if err != nil {
		return err
	}
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-c.turn }()
	if c.closed() {
		return errClosed // a free turn is taken after Close too
	}
	// A ROUTING_BUSY received while waiting extends the wait.
	for d := c.flow.Delay(); d > 0; d = c.flow.Delay() {
		if err := sleep(ctx, c.closing, d); err != nil {
			return err
		}
	}
	frame, err := knxnetip.Marshal(&knxnetip.RoutingIndication{CEMI: b})
	if err != nil {
		return err
	}
	if c.timer != nil {
		w, err := secure.Seal(c.o.secure.key, 0, c.timer.Next(), c.o.serial, randUint16(), frame)
		if err != nil {
			return err
		}
		if frame, err = knxnetip.Marshal(w); err != nil {
			return err
		}
	}
	c.flow.Sent()
	if err := c.transmit(ctx, frame, knxnetip.RoutingIndicationType); err != nil {
		if c.closed() {
			// Close came during the write.
			return fmt.Errorf("%w: %w", knx.ErrClosed, err)
		}
		if d, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) && !time.Now().Before(d) {
			// The write ended at ctx's deadline, the write deadline
			// transmit set.
			return fmt.Errorf("%w: %w", err, context.DeadlineExceeded)
		}
		return err
	}
	return nil
}

// deadline makes the error of a call whose context deadline passed match
// knx.ErrTimeout too: Send, Receive and Listen. An error whose message
// names the package already does not get the name again.
func deadline(err error) error {
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, knx.ErrTimeout) {
		return err
	}
	if strings.HasPrefix(err.Error(), "routing: ") {
		return fmt.Errorf("%w: %w", knx.ErrTimeout, err)
	}
	return fmt.Errorf("%w: routing: %w", knx.ErrTimeout, err)
}

// errClosed is the error of a Send after Close.
var errClosed = fmt.Errorf("routing: send: %w", knx.ErrClosed)

// closed reports whether Close has begun.
func (c *Conn) closed() bool {
	select {
	case <-c.closing:
		return true
	default:
		return false
	}
}

// acquire takes the send turn. A turn that is free is taken at once;
// otherwise acquire waits for it until ctx ends or the Conn closes.
func (c *Conn) acquire(ctx context.Context) error {
	select {
	case c.turn <- struct{}{}:
		return nil
	default:
	}
	select {
	case c.turn <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closing:
		return knx.ErrClosed
	}
}

func randUint16() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return uint16(b[0])<<8 | uint16(b[1])
}

// transmit sends a frame to the group and remembers it to recognise its
// echo.
func (c *Conn) transmit(ctx context.Context, frame []byte, service knxnetip.ServiceType) error {
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
	wd := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(wd) {
		wd = d
	}
	_ = c.sock.SetWriteDeadline(wd)
	if _, err := c.sock.WriteToUDPAddrPort(frame, c.group); err != nil {
		return fmt.Errorf("routing: send: %w", err)
	}
	c.o.metrics.OnFrameSent(net.UDPAddrFromAddrPort(c.group), uint16(service), len(frame))
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
// router. When ctx's deadline passes first the error matches
// knx.ErrTimeout and context.DeadlineExceeded; when ctx is cancelled,
// context.Canceled; after Close, knx.ErrClosed.
func (c *Conn) Receive(ctx context.Context) (cemi.Frame, error) {
	select {
	case f := <-c.inbound:
		return f, nil
	case <-ctx.Done():
		return nil, deadline(ctx.Err())
	case <-c.closing:
		return nil, knx.ErrClosed
	}
}

// Events returns ROUTING_BUSY and ROUTING_LOST_MESSAGE notifications
// (bounded; older ones are dropped when not read).
func (c *Conn) Events() <-chan Event { return c.events }

// readLoop reads the socket with read until it is closed. After a read
// error it reads on, but only after a pause that grows while errors
// follow each other (internal/backoff), and it ends when the Conn closes
// during a pause.
func (c *Conn) readLoop(read func([]byte) (int, netip.AddrPort, error)) {
	defer c.wg.Done()
	buf := make([]byte, knxnetip.MaxFrameLen+1)
	var retry backoff.Loop
	for {
		n, from, err := read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.o.logger.Debugf("routing: read: %v", err)
			if !retry.Wait(c.closing) {
				return
			}
			continue
		}
		retry.Reset()
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		fa := net.UDPAddrFromAddrPort(from)
		if c.o.loopback {
			h := sha256.Sum256(buf[:n])
			c.mu.Lock()
			// Kept until it expires: a system may loop a datagram back
			// more than once.
			sent, own := c.echoes[h]
			own = own && time.Since(sent) < 2*time.Second
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
		if c.timer != nil {
			if m = c.unwrap(fa, m); m == nil {
				continue
			}
		}
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
			c.flow.Busy(time.Duration(m.WaitTime) * time.Millisecond)
			c.event(Event{From: from, Busy: m})
		case *knxnetip.RoutingLostMessage:
			c.event(Event{From: from, Lost: m})
		}
	}
}

// unwrap verifies a frame of secure routing and returns the frame it
// carries; TIMER_NOTIFY frames go to the timer. It returns nil for
// frames that are not delivered.
func (c *Conn) unwrap(from *net.UDPAddr, m knxnetip.Message) knxnetip.Message {
	switch w := m.(type) {
	case *knxnetip.TimerNotify:
		if !c.timer.HandleNotify(w) {
			c.o.metrics.OnDropped(from, "authentication")
		}
		return nil
	case *knxnetip.SecureWrapper:
		if !c.timer.Authenticated() {
			c.o.metrics.OnDropped(from, "timer_unsynchronised")
			return nil
		}
		if w.SessionID != 0 {
			c.o.metrics.OnDropped(from, "session")
			return nil
		}
		frame, err := secure.Open(c.o.secure.key, w)
		if err != nil {
			c.o.metrics.OnDecodeError(from, err)
			return nil
		}
		if !c.timer.Accept(w) {
			c.o.metrics.OnDropped(from, "timer")
			return nil
		}
		inner, err := knxnetip.Parse(frame)
		if err != nil {
			c.o.metrics.OnDecodeError(from, err)
			return nil
		}
		return inner
	default:
		c.o.metrics.OnDropped(from, "unsecured")
		return nil
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
		if c.timer != nil {
			c.timer.Stop()
		}
		_ = c.sock.Close()
		c.wg.Wait()
	})
	return nil
}
