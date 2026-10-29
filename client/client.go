// SPDX-License-Identifier: MIT

// Package client is KNX group communication over a link: a KNXnet/IP
// tunnel (package tunnel) or routing (package routing). It writes, reads
// and answers group values, typed with datapoint types (package dpt) or
// raw, and delivers the group telegrams it sees to subscriptions and
// callbacks.
//
//	c, err := client.DialTunnel(ctx, "192.168.1.10")
//	if err != nil { ... }
//	defer c.Close()
//	err = c.GroupWrite(ctx, knx.MustParseGroupAddress("1/2/3"), true)
//	r, err := c.GroupRead(ctx, knx.MustParseGroupAddress("1/2/4"), client.WithDPT("9.001"))
//
// A group read is a request on the bus: no response is guaranteed (no
// device may have the R flag for that address), and several devices may
// answer. GroupRead returns the first response within the deadline;
// GroupReadAll collects all of them during a window.
package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/dpt"
	"github.com/otfabric/go-knx/routing"
	"github.com/otfabric/go-knx/tunnel"
)

// DefaultReadTimeout bounds GroupRead when the context has no deadline.
const DefaultReadTimeout = 3 * time.Second

// Link carries cEMI frames: *tunnel.Conn and *routing.Conn implement it.
type Link interface {
	Send(ctx context.Context, f cemi.Frame) error
	Receive(ctx context.Context) (cemi.Frame, error)
	Close() error
}

// Telegram is a group telegram seen on the link.
type Telegram struct {
	Time    time.Time
	Source  knx.IndividualAddress
	Group   knx.GroupAddress
	Service apdu.APCI
	// Value is the data of a write or response (empty for a read).
	Value apdu.GroupValue
	Frame *cemi.LData
}

// Decode decodes the value with datapoint type id.
func (t Telegram) Decode(id string) (any, error) {
	ty, err := dpt.Lookup(id)
	if err != nil {
		return nil, err
	}
	return ty.Decode(t.Value.Data)
}

// Client is group communication over a link. It owns the link.
type Client struct {
	link   Link
	source knx.IndividualAddress
	prio   knx.Priority
	logger knx.Logger

	mu      sync.Mutex
	subs    map[*Subscription]struct{}
	waiters map[*waiter]struct{}
	hooks   map[int]func(Telegram)
	hookID  int
	err     error

	done   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// Option configures a Client.
type Option func(*Client)

// WithSource sets the source address of the telegrams (default 0.0.0,
// which a tunnelling server replaces by the tunnel's address; set it for
// routing).
func WithSource(a knx.IndividualAddress) Option { return func(c *Client) { c.source = a } }

// WithPriority sets the priority of the telegrams (default low).
func WithPriority(p knx.Priority) Option { return func(c *Client) { c.prio = p } }

// WithLogger sets the logger.
func WithLogger(l knx.Logger) Option {
	return func(c *Client) {
		if l != nil {
			c.logger = l
		}
	}
}

// New returns a client over link and starts reading it.
func New(link Link, opts ...Option) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{link: link, prio: knx.PriorityLow, logger: knx.NopLogger(), subs: map[*Subscription]struct{}{},
		waiters: map[*waiter]struct{}{}, hooks: map[int]func(Telegram){}, done: make(chan struct{}), cancel: cancel}
	for _, o := range opts {
		o(c)
	}
	c.wg.Add(1)
	go c.readLoop(ctx)
	return c
}

// DialTunnel connects a tunnel to addr and returns a client over it.
func DialTunnel(ctx context.Context, addr string, topts []tunnel.Option, opts ...Option) (*Client, error) {
	t, err := tunnel.Dial(ctx, addr, topts...)
	if err != nil {
		return nil, err
	}
	return New(t, opts...), nil
}

// ListenRouting joins the routing group and returns a client over it.
func ListenRouting(ctx context.Context, ropts []routing.Option, opts ...Option) (*Client, error) {
	r, err := routing.Listen(ctx, ropts...)
	if err != nil {
		return nil, err
	}
	return New(r, opts...), nil
}

// Link returns the link.
func (c *Client) Link() Link { return c.link }

// Done is closed when the client stopped reading: closed, or the link
// failed (Err).
func (c *Client) Done() <-chan struct{} { return c.done }

// Err returns the error the link failed with, nil after Close.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close closes the link and ends the subscriptions.
func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		err = c.link.Close()
		c.cancel()
		c.wg.Wait()
	})
	return err
}

// WriteOption configures a write, response or read.
type WriteOption func(*wopts) error

type wopts struct {
	t *dpt.Type
}

// WithDPT sets the datapoint type of the value ("9.001").
func WithDPT(id string) WriteOption {
	return func(o *wopts) error {
		t, err := dpt.Lookup(id)
		if err != nil {
			return err
		}
		o.t = t
		return nil
	}
}

// WithType sets the datapoint type of the value.
func WithType(t *dpt.Type) WriteOption { return func(o *wopts) error { o.t = t; return nil } }

func groupValue(v any, o wopts) (apdu.GroupValue, error) {
	if o.t != nil {
		raw, err := o.t.Encode(v)
		if err != nil {
			return apdu.GroupValue{}, err
		}
		return apdu.GroupValue{Data: raw, Small: o.t.Small()}, nil
	}
	switch x := v.(type) {
	case apdu.GroupValue:
		return x, nil
	case bool:
		if x {
			return apdu.GroupValue{Data: []byte{1}, Small: true}, nil
		}
		return apdu.GroupValue{Data: []byte{0}, Small: true}, nil
	case []byte:
		return apdu.GroupValue{Data: x}, nil
	}
	return apdu.GroupValue{}, fmt.Errorf("%w: client: %T value needs a datapoint type (WithDPT)", knx.ErrInvalidValue, v)
}

func options(opts []WriteOption) (wopts, error) {
	var o wopts
	for _, f := range opts {
		if err := f(&o); err != nil {
			return o, err
		}
	}
	return o, nil
}

// GroupWrite sends A_GroupValue_Write of v to g. v is a bool (DPT 1), an
// apdu.GroupValue or []byte (raw), or any value of the type set by
// WithDPT. Over a tunnel it returns once the server confirmed the
// telegram (L_Data.con).
func (c *Client) GroupWrite(ctx context.Context, g knx.GroupAddress, v any, opts ...WriteOption) error {
	o, err := options(opts)
	if err != nil {
		return err
	}
	gv, err := groupValue(v, o)
	if err != nil {
		return err
	}
	tpdu, err := apdu.GroupValueWrite(gv)
	if err != nil {
		return err
	}
	return c.send(ctx, g, tpdu)
}

// GroupRespond sends A_GroupValue_Response of v to g.
func (c *Client) GroupRespond(ctx context.Context, g knx.GroupAddress, v any, opts ...WriteOption) error {
	o, err := options(opts)
	if err != nil {
		return err
	}
	gv, err := groupValue(v, o)
	if err != nil {
		return err
	}
	tpdu, err := apdu.GroupValueResponse(gv)
	if err != nil {
		return err
	}
	return c.send(ctx, g, tpdu)
}

func (c *Client) send(ctx context.Context, g knx.GroupAddress, tpdu []byte) error {
	code := cemi.LDataReq
	if _, routed := c.link.(*routing.Conn); routed {
		code = cemi.LDataInd
	}
	return c.link.Send(ctx, cemi.NewGroupFrame(code, c.source, g, c.prio, tpdu))
}

// Response is an answer to a group read.
type Response struct {
	Telegram
	// Decoded is the value decoded with the WithDPT type (nil without).
	Decoded any
}

type waiter struct {
	g  knx.GroupAddress
	ch chan Telegram
}

// GroupRead sends A_GroupValue_Read to g and returns the first
// A_GroupValue_Response to g before ctx's deadline (DefaultReadTimeout
// without one). It returns an error matching knx.ErrTimeout when no
// device answered. With WithDPT the value is decoded too.
func (c *Client) GroupRead(ctx context.Context, g knx.GroupAddress, opts ...WriteOption) (Response, error) {
	rs, err := c.read(ctx, g, true, opts)
	if err != nil {
		return Response{}, err
	}
	return rs[0], nil
}

// GroupReadAll sends A_GroupValue_Read to g and returns every response to
// g received during window (possibly none).
func (c *Client) GroupReadAll(ctx context.Context, g knx.GroupAddress, window time.Duration, opts ...WriteOption) ([]Response, error) {
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	return c.read(ctx, g, false, opts)
}

func (c *Client) read(ctx context.Context, g knx.GroupAddress, first bool, opts []WriteOption) ([]Response, error) {
	o, err := options(opts)
	if err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultReadTimeout)
		defer cancel()
	}
	w := &waiter{g: g, ch: make(chan Telegram, 16)}
	c.mu.Lock()
	c.waiters[w] = struct{}{}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiters, w)
		c.mu.Unlock()
	}()
	if err := c.send(ctx, g, apdu.GroupValueRead()); err != nil {
		return nil, err
	}
	var out []Response
	for {
		select {
		case t := <-w.ch:
			r := Response{Telegram: t}
			if o.t != nil {
				v, err := o.t.Decode(t.Value.Data)
				if err != nil {
					return nil, err
				}
				r.Decoded = v
			}
			out = append(out, r)
			if first {
				return out, nil
			}
		case <-ctx.Done():
			if first {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return nil, fmt.Errorf("%w: client: no response to the read of %s", knx.ErrTimeout, g)
				}
				return nil, ctx.Err()
			}
			return out, nil
		case <-c.done:
			if err := c.Err(); err != nil {
				return nil, err
			}
			return nil, knx.ErrClosed
		}
	}
}

// OnTelegram calls f, from the client's reader goroutine, for every group
// telegram; it must not block. The returned function removes it.
func (c *Client) OnTelegram(f func(Telegram)) (remove func()) {
	c.mu.Lock()
	c.hookID++
	id := c.hookID
	c.hooks[id] = f
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.hooks, id)
		c.mu.Unlock()
	}
}

// Subscription receives group telegrams, optionally filtered by group
// address, through a bounded channel. Telegrams that do not fit are
// dropped and counted.
type Subscription struct {
	c       *Client
	filter  map[knx.GroupAddress]bool
	ch      chan Telegram
	mu      sync.Mutex
	dropped uint64
	closed  bool
}

// Subscribe returns a subscription to the telegrams to groups (all when
// empty), with a channel of buffer telegrams (minimum 1).
func (c *Client) Subscribe(buffer int, groups ...knx.GroupAddress) *Subscription {
	if buffer < 1 {
		buffer = 1
	}
	s := &Subscription{c: c, ch: make(chan Telegram, buffer)}
	if len(groups) > 0 {
		s.filter = map[knx.GroupAddress]bool{}
		for _, g := range groups {
			s.filter[g] = true
		}
	}
	c.mu.Lock()
	select {
	case <-c.done:
		s.closed = true
		close(s.ch)
	default:
		c.subs[s] = struct{}{}
	}
	c.mu.Unlock()
	return s
}

// C returns the channel; it is closed by Unsubscribe or when the client
// stops.
func (s *Subscription) C() <-chan Telegram { return s.ch }

// Dropped returns the number of telegrams dropped because the channel was
// full.
func (s *Subscription) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Unsubscribe ends the subscription and closes its channel.
func (s *Subscription) Unsubscribe() {
	s.c.mu.Lock()
	delete(s.c.subs, s)
	s.c.mu.Unlock()
	s.close()
}

func (s *Subscription) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

func (s *Subscription) deliver(t Telegram) {
	if s.filter != nil && !s.filter[t.Group] {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- t:
	default:
		s.dropped++
	}
}

func (c *Client) readLoop(ctx context.Context) {
	defer c.wg.Done()
	defer func() {
		c.mu.Lock()
		subs := c.subs
		c.subs = map[*Subscription]struct{}{}
		close(c.done)
		c.mu.Unlock()
		for s := range subs {
			s.close()
		}
	}()
	for {
		f, err := c.link.Receive(ctx)
		if err != nil {
			if !errors.Is(err, knx.ErrClosed) && !errors.Is(err, context.Canceled) {
				c.mu.Lock()
				c.err = err
				c.mu.Unlock()
			}
			return
		}
		ld, ok := f.(*cemi.LData)
		if !ok || ld.MsgCode == cemi.LDataCon {
			continue
		}
		g, ok := ld.Group()
		if !ok {
			continue
		}
		svc, v, err := apdu.ParseGroupValue(ld.TPDU)
		if err != nil {
			continue
		}
		t := Telegram{Time: time.Now(), Source: ld.Source, Group: g, Service: svc, Value: v, Frame: ld}
		c.mu.Lock()
		subs := make([]*Subscription, 0, len(c.subs))
		for s := range c.subs {
			subs = append(subs, s)
		}
		hooks := make([]func(Telegram), 0, len(c.hooks))
		for _, h := range c.hooks {
			hooks = append(hooks, h)
		}
		if svc == apdu.GroupValueResponseService {
			for w := range c.waiters {
				if w.g == g {
					select {
					case w.ch <- t:
					default:
					}
				}
			}
		}
		c.mu.Unlock()
		for _, s := range subs {
			s.deliver(t)
		}
		for _, h := range hooks {
			h(t)
		}
	}
}
