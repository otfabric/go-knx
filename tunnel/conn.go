// SPDX-License-Identifier: MIT

// Package tunnel is a KNXnet/IP tunnelling client over UDP: it connects
// to a KNXnet/IP server (an IP interface or router), sends cEMI frames
// with acknowledgement and retransmission, receives telegrams with
// sequence checking and duplicate suppression, keeps the connection alive
// with heartbeats and, optionally, reconnects.
//
// The connection state machine:
//
//	disconnected ──Dial──▶ connecting ──CONNECT_RESPONSE ok──▶ connected
//	connected ──heartbeat failed / server DISCONNECT / no ACK──▶ lost
//	lost ──WithReconnect──▶ reconnecting ──▶ connected (new channel)
//	lost ──otherwise──▶ closed (Err reports why)
//	any ──Close──▶ DISCONNECT_REQUEST ──▶ closed
//
// One goroutine reads the socket and one sends heartbeats; both end when
// the Conn is closed. Over TCP every write is bounded by the request
// timeout; a write the server does not take in time loses the connection,
// so neither Send nor Close waits on a server that stops reading. A Conn is safe for concurrent use; sends are
// serialised, as tunnelling allows one unacknowledged request at a time:
// a Send waits for its turn until its context ends or the Conn closes.
package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/backoff"
	"github.com/otfabric/go-knx/internal/udp"
	"github.com/otfabric/go-knx/knxnetip"
)

// Conn is a KNXnet/IP tunnelling connection.
type Conn struct {
	o      options
	tr     transport
	server netip.AddrPort // control endpoint
	hpai   knxnetip.HPAI

	mu      sync.Mutex
	state   knx.State
	channel uint8
	dataEP  netip.AddrPort
	addr    knx.IndividualAddress
	rxSeq   uint8
	txSeq   uint8
	err     error
	gen     uint64 // incremented on every (re)connection
	// remoteClosed is set when the server disconnected the channel of
	// generation gen: there is nothing left to disconnect.
	remoteClosed bool

	// turn is the send turn: Send and the feature calls hold it for one
	// request and its acknowledgement. Waiting for it ends with the
	// caller's context or with the Conn.
	turn chan struct{}
	// unacked is the request of a caller that left before its
	// TUNNELLING_ACK arrived; the next holder of the turn settles it.
	// Only the holder of the turn reads or writes it.
	unacked *unackedRequest
	ackCh   chan *knxnetip.TunnellingAck
	featCh  chan *knxnetip.TunnellingFeature
	connCh  chan *knxnetip.ConnectResponse
	csCh    chan *knxnetip.ConnectionStateResponse
	discCh  chan *knxnetip.DisconnectResponse

	conMu   sync.Mutex
	conWait *confirmWait

	inbound chan cemi.Frame
	lost    chan lostEvent
	// stopping is closed when Close begins: the supervisor ends, and a
	// reconnection it runs disconnects the channel it opened.
	stopping  chan struct{}
	superDone chan struct{} // closed when the supervisor ended; nil before it starts
	closing   chan struct{}
	done      chan struct{}
	closeMu   sync.Once
	wg        sync.WaitGroup
}

type lostEvent struct {
	gen uint64
	err error
}

// unackedRequest is a request that was written but whose acknowledgement
// nobody waits for any more: the server may have taken it, so its
// sequence number is not free for another frame.
type unackedRequest struct {
	gen      uint64
	ch, seq  uint8
	deadline time.Time // end of the request timeout of its last transmission
	lost     bool      // the request timeout passed without an acknowledgement
}

type confirmWait struct {
	dst   uint16
	group bool
	tpdu  []byte
	ch    chan *cemi.LData
}

// Dial connects to the KNXnet/IP server at addr ("192.168.1.10",
// "192.168.1.10:3671") and establishes a tunnelling connection. When the
// deadline of ctx passes first, Dial returns an error matching
// knx.ErrTimeout and context.DeadlineExceeded.
func Dial(ctx context.Context, addr string, opts ...Option) (*Conn, error) {
	c, err := dial(ctx, addr, opts...)
	if err != nil {
		return nil, deadline(err)
	}
	return c, nil
}

// dial is Dial; Dial makes the error of an expired deadline match
// knx.ErrTimeout too.
func dial(ctx context.Context, addr string, opts ...Option) (*Conn, error) {
	o := defaultOptions()
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}
	server, err := udp.ResolveEndpoint(ctx, addr, knxnetip.Port)
	if err != nil {
		return nil, err
	}
	local := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	if o.local != "" {
		if local, err = udp.ResolveEndpoint(ctx, o.local, 0); err != nil {
			return nil, err
		}
	}
	if o.secure != nil && !o.udp {
		o.tcp = true // KNX IP Secure tunnels over TCP unless WithUDP
	}
	if o.tcp && o.udp {
		return nil, invalid("WithTCP and WithUDP exclude each other")
	}
	if o.tcp && o.reconnect {
		return nil, invalid("WithTCP and WithReconnect: reconnect over TCP is not implemented")
	}
	if o.dial != nil && !o.tcp {
		return nil, invalid("WithDialer needs a TCP tunnel")
	}
	if o.dial != nil && o.local != "" {
		return nil, invalid("WithDialer and WithLocalAddr exclude each other")
	}
	// closing is the Conn's: it also ends the pause of the UDP reader
	// after a read error.
	closing := make(chan struct{})
	var tr transport
	if o.tcp {
		tc, err := dialTCP(ctx, o, local, server)
		if err != nil {
			return nil, err
		}
		// Every write is bounded by the request timeout: a server that
		// stops reading is a lost connection, not a stuck writer.
		tr = &tcpTransport{c: tc, server: server, writeTimeout: o.requestTimeout}
	} else {
		sock, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(local))
		if err != nil {
			return nil, fmt.Errorf("tunnel: listen %s: %w", local, err)
		}
		tr = udpTransport{c: sock, done: closing}
	}
	var hpai knxnetip.HPAI
	switch {
	case o.tcp:
		hpai = knxnetip.TCPHPAI()
	case o.nat:
		hpai = knxnetip.RouteBackHPAI()
	default:
		bound := udp.AddrPortOf(tr.localAddr())
		ip := bound.Addr()
		if !ip.IsValid() || ip.IsUnspecified() {
			if ip, err = udp.LocalIPFor(server); err != nil {
				_ = tr.close()
				return nil, fmt.Errorf("tunnel: no route to %s: %w", server, err)
			}
		}
		hpai = knxnetip.NewHPAI(netip.AddrPortFrom(ip, bound.Port()))
	}
	if o.secure != nil {
		st, err := handshake(ctx, tr, server, hpai, *o.secure, o.connectTimeout, o.sessionKeepAlive)
		if err != nil {
			_ = tr.close()
			return nil, err
		}
		tr = st
	}
	c := &Conn{
		o: o, tr: tr, server: server, hpai: hpai,
		turn:     make(chan struct{}, 1),
		featCh:   make(chan *knxnetip.TunnellingFeature, 4),
		ackCh:    make(chan *knxnetip.TunnellingAck, 1),
		connCh:   make(chan *knxnetip.ConnectResponse, 1),
		csCh:     make(chan *knxnetip.ConnectionStateResponse, 1),
		discCh:   make(chan *knxnetip.DisconnectResponse, 1),
		inbound:  make(chan cemi.Frame, o.queueSize),
		lost:     make(chan lostEvent, 1),
		stopping: make(chan struct{}),
		closing:  closing,
		done:     make(chan struct{}),
	}
	c.setState(knx.StateConnecting, nil)
	c.wg.Add(1)
	go c.readLoop()
	if err := c.connect(ctx); err != nil {
		c.shutdown(err)
		return nil, err
	}
	c.wg.Add(2)
	c.superDone = make(chan struct{})
	go c.heartbeatLoop()
	// Reconnects outlive Dial: they keep the values of ctx (tracing and
	// the like) but not its cancellation or deadline, which bound the
	// first connect only. Close cancels them.
	go c.supervise(context.WithoutCancel(ctx))
	return c, nil
}

// dialTCP opens the TCP connection of a tunnel: with the dialer of
// WithDialer, or else a net.Dialer bound to local when WithLocalAddr set
// it.
func dialTCP(ctx context.Context, o options, local, server netip.AddrPort) (net.Conn, error) {
	if o.dial == nil {
		d := net.Dialer{Timeout: o.connectTimeout}
		if o.local != "" {
			d.LocalAddr = net.TCPAddrFromAddrPort(local)
		}
		tc, err := d.DialContext(ctx, "tcp4", server.String())
		if err != nil {
			return nil, fmt.Errorf("tunnel: dial tcp %s: %w", server, err)
		}
		return tc, nil
	}
	dctx, cancel := context.WithTimeout(ctx, o.connectTimeout)
	defer cancel()
	tc, err := o.dial(dctx, "tcp4", server.String())
	if err != nil {
		if tc != nil {
			_ = tc.Close()
		}
		return nil, fmt.Errorf("tunnel: dial tcp %s: %w", server, err)
	}
	if tc == nil {
		return nil, invalid("the dialer of WithDialer returned no connection to %s", server)
	}
	return tc, nil
}

// IndividualAddress returns the individual address the server assigned to
// the connection.
func (c *Conn) IndividualAddress() knx.IndividualAddress {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addr
}

// Channel returns the communication channel identifier.
func (c *Conn) Channel() uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.channel
}

// State returns the connection state.
func (c *Conn) State() knx.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Server returns the control endpoint of the server.
func (c *Conn) Server() netip.AddrPort { return c.server }

// LocalAddr returns the local endpoint of the socket.
func (c *Conn) LocalAddr() net.Addr { return c.tr.localAddr() }

// TCP reports a connection over TCP (KNXnet/IP core v2).
func (c *Conn) TCP() bool { return c.tr.stream() }

// Done is closed when the Conn is closed, by Close or because the
// connection was lost without reconnection.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns why the Conn closed: nil after Close, otherwise an error
// matching knx.ErrConnectionLost.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) setState(s knx.State, err error) {
	c.mu.Lock()
	changed := c.state != s
	c.state = s
	c.mu.Unlock()
	if changed && c.o.stateFunc != nil {
		c.o.stateFunc(s, err)
	}
}

func (c *Conn) write(to netip.AddrPort, m knxnetip.Message) error {
	return c.writeContext(context.Background(), to, m)
}

// writeContext is write bounded by ctx: a write ctx ends before it
// started returns ctx.Err() unwrapped.
func (c *Conn) writeContext(ctx context.Context, to netip.AddrPort, m knxnetip.Message) error {
	b, err := knxnetip.Marshal(m)
	if err != nil {
		return err
	}
	if err := c.tr.writeContext(ctx, b, to); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("tunnel: write %s to %s: %w", m.Service(), to, err)
	}
	c.o.metrics.OnFrameSent(net.UDPAddrFromAddrPort(to), uint16(m.Service()), len(b))
	return nil
}

// connect performs CONNECT_REQUEST / CONNECT_RESPONSE.
func (c *Conn) connect(ctx context.Context) error {
	drain(c.connCh)
	cri := knxnetip.TunnelCRI(c.o.layer)
	if c.o.devmgmt {
		cri = knxnetip.CRI{Type: knxnetip.DeviceManagementConnection}
	}
	if c.o.hasAddress {
		cri.HasAddress, cri.Address = true, c.o.address
	}
	req := &knxnetip.ConnectRequest{Control: c.hpai, Data: c.hpai, CRI: cri}
	select {
	case <-c.stopping:
		return knx.ErrClosed
	default:
	}
	if err := c.write(c.server, req); err != nil {
		return err
	}
	end := time.Now().Add(c.o.connectTimeout)
	t := time.NewTimer(c.o.connectTimeout)
	defer t.Stop()
	select {
	case resp := <-c.connCh:
		if resp.Status != knxnetip.StatusNoError {
			return &knxnetip.StatusError{Service: knxnetip.ConnectResponseType, Status: resp.Status}
		}
		if want := cri.Type; resp.CRD.Type != want {
			return fmt.Errorf("%w: tunnel: CONNECT_RESPONSE with a %s CRD", knx.ErrMalformed, resp.CRD.Type)
		}
		data := resp.Data.Addr
		if c.o.nat || c.o.tcp || resp.Data.IsRouteBack() {
			data = c.server
		}
		c.mu.Lock()
		c.channel, c.dataEP, c.addr = resp.Channel, data, resp.CRD.Address
		c.rxSeq, c.txSeq = 0, 0
		c.gen++
		c.remoteClosed = false
		c.mu.Unlock()
		c.setState(knx.StateConnected, nil)
		c.o.metrics.OnConnect(net.UDPAddrFromAddrPort(c.server), resp.Channel)
		c.o.logger.Infof("tunnel: connected to %s, channel %d, address %s", c.server, resp.Channel, resp.CRD.Address)
		return nil
	case <-t.C:
		return fmt.Errorf("%w: tunnel: no CONNECT_RESPONSE from %s within %v", knx.ErrTimeout, c.server, c.o.connectTimeout)
	case <-ctx.Done():
		select {
		case <-c.stopping:
			c.abandonConnect(end)
			return knx.ErrClosed
		default:
		}
		return ctx.Err()
	case <-c.stopping:
		c.abandonConnect(end)
		return knx.ErrClosed
	}
}

// abandonConnectWait bounds the wait of Close for the answer to a
// CONNECT_REQUEST it interrupted.
const abandonConnectWait = time.Second

// abandonConnect handles the CONNECT_REQUEST of a reconnection that Close
// interrupted: it waits for the answer, for at most abandonConnectWait
// and not past end, the end of the connect timeout, and disconnects the
// channel the answer opened, so that the server does not keep it.
func (c *Conn) abandonConnect(end time.Time) {
	wait := min(time.Until(end), abandonConnectWait)
	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case resp := <-c.connCh:
		if resp.Status != knxnetip.StatusNoError {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), closeWriteTimeout)
		defer cancel()
		if err := c.writeContext(ctx, c.server, &knxnetip.DisconnectRequest{Channel: resp.Channel, Control: c.hpai}); err != nil {
			c.o.logger.Debugf("tunnel: disconnect channel %d of the interrupted reconnection: %v", resp.Channel, err)
		}
	case <-t.C:
	}
}

func drain[T any](ch chan T) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// Send sends a cEMI frame on the tunnel and waits for its
// acknowledgement. The request is repeated once if no TUNNELLING_ACK
// arrives within the request timeout; if the second attempt fails too the
// connection is considered lost. For an L_Data.req Send also waits for
// the L_Data.con (unless WithConfirm(false)) and returns an error
// matching knx.ErrNotConfirmed if it reports an error or does not arrive.
//
// Send never repeats a frame on its own beyond that one TUNNELLING_REQUEST
// repetition. An error matching knx.ErrConnectionLost (or ErrNotConfirmed)
// does not tell whether the frame reached the bus: the server may have
// received it before the tunnel was lost. With WithReconnect the tunnel
// comes back on a new channel, but the frame is not resent there; the
// caller decides whether repeating it is safe (a read is, a toggle may not
// be).
//
// Sends take turns, and a Send that waits for its turn returns when ctx
// ends (ctx's error) or the Conn closes. A Send whose context deadline
// passes, in any of its waits, returns an error matching knx.ErrTimeout
// and context.DeadlineExceeded. When ctx ends after the request
// was written and before its TUNNELLING_ACK, Send returns ctx's error and
// the request stays outstanding: it is not repeated, the server may have
// taken it, and its sequence number is used for no other frame. The next
// Send or feature call first waits for that acknowledgement, for what is
// left of the request timeout, and then sends under the next sequence
// number; when the acknowledgement did not come, the connection is
// considered lost (knx.ErrConnectionLost).
func (c *Conn) Send(ctx context.Context, f cemi.Frame) error {
	return deadline(c.send(ctx, f))
}

// send is Send; Send makes the error of an expired deadline match
// knx.ErrTimeout too.
func (c *Conn) send(ctx context.Context, f cemi.Frame) error {
	b, err := cemi.Marshal(f)
	if err != nil {
		return err
	}
	if err := c.acquire(ctx); err != nil {
		return err
	}
	defer c.release()
	if err := c.settle(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	state, ch, seq, dataEP, gen := c.state, c.channel, c.txSeq, c.dataEP, c.gen
	c.mu.Unlock()
	switch state {
	case knx.StateConnected:
	case knx.StateClosed:
		return knx.ErrClosed
	default:
		return fmt.Errorf("%w: tunnel: %s", knx.ErrConnectionLost, state)
	}

	var wait *confirmWait
	if ld, ok := f.(*cemi.LData); ok && ld.MsgCode == cemi.LDataReq && c.o.waitConfirm {
		wait = &confirmWait{dst: ld.Destination, group: ld.IsGroup(), tpdu: ld.TPDU, ch: make(chan *cemi.LData, 1)}
		c.conMu.Lock()
		c.conWait = wait
		c.conMu.Unlock()
		defer func() {
			c.conMu.Lock()
			if c.conWait == wait {
				c.conWait = nil
			}
			c.conMu.Unlock()
		}()
	}

	var req knxnetip.Message = &knxnetip.TunnellingRequest{Channel: ch, Seq: seq, CEMI: b}
	if c.o.devmgmt {
		req = &knxnetip.DeviceConfigurationRequest{Channel: ch, Seq: seq, CEMI: b}
	}
	// A frame too long for a KNXnet/IP datagram is the caller's error, not
	// a lost connection: refuse it before it reaches the socket.
	if _, err := knxnetip.Marshal(req); err != nil {
		return err
	}
	if c.tr.stream() {
		// TCP is reliable: tunnelling requests are not acknowledged. The
		// write is bounded by ctx and the write timeout; one ctx ends
		// before it started leaves the connection up.
		if err := c.writeContext(ctx, dataEP, req); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return c.sendError(gen, err)
		}
		c.advance(gen)
	} else if err := c.exchange(ctx, gen, ch, seq, dataEP, req, func(err error) error { return c.sendError(gen, err) }); err != nil {
		return err
	}

	if wait == nil {
		return nil
	}
	t := time.NewTimer(c.o.confirmTimeout)
	defer t.Stop()
	select {
	case con := <-wait.ch:
		if con.ConfirmError() {
			return fmt.Errorf("%w: tunnel: L_Data.con reports an error", knx.ErrNotConfirmed)
		}
		return nil
	case <-t.C:
		return fmt.Errorf("%w: tunnel: no L_Data.con within %v", knx.ErrNotConfirmed, c.o.confirmTimeout)
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closing:
		return knx.ErrClosed
	}
}

// deadline makes the error of a call whose context deadline passed match
// knx.ErrTimeout too: Send, the feature calls and Dial. An error whose
// message names the package already does not get the name again.
func deadline(err error) error {
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, knx.ErrTimeout) {
		return err
	}
	if strings.HasPrefix(err.Error(), "tunnel: ") {
		return fmt.Errorf("%w: %w", knx.ErrTimeout, err)
	}
	return fmt.Errorf("%w: tunnel: %w", knx.ErrTimeout, err)
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

func (c *Conn) release() { <-c.turn }

// advance consumes the sequence number of an acknowledged request of
// connection generation gen.
func (c *Conn) advance(gen uint64) {
	c.mu.Lock()
	if c.gen == gen {
		c.txSeq++
	}
	c.mu.Unlock()
}

// exchange is the sender side of the sequence counter over UDP: it
// writes req, which carries sequence number seq, and waits for its
// TUNNELLING_ACK, repeating the request once after the request timeout.
// An acknowledged request consumes the sequence number; a request that is
// not acknowledged twice loses the connection. A write that fails is
// reported through writeError. When ctx ends during the wait, the request
// is left to settle. The caller holds the send turn.
func (c *Conn) exchange(ctx context.Context, gen uint64, ch, seq uint8, dataEP netip.AddrPort, req knxnetip.Message, writeError func(error) error) error {
	drain(c.ackCh)
	for attempt := range 2 {
		if attempt > 0 {
			c.o.metrics.OnRetransmit(net.UDPAddrFromAddrPort(dataEP), ch)
			c.o.logger.Debugf("tunnel: no ACK for sequence %d, repeating", seq)
		}
		if err := c.write(dataEP, req); err != nil {
			return writeError(err)
		}
		deadline := time.Now().Add(c.o.requestTimeout)
		t := time.NewTimer(c.o.requestTimeout)
	wait:
		for {
			select {
			case ack := <-c.ackCh:
				if ack.Channel != ch || ack.Seq != seq {
					continue // a late ACK of an earlier request
				}
				t.Stop()
				if ack.Status != knxnetip.StatusNoError {
					return &knxnetip.StatusError{Service: knxnetip.TunnellingAckType, Status: ack.Status}
				}
				c.advance(gen)
				return nil
			case <-t.C:
				break wait
			case <-ctx.Done():
				t.Stop()
				c.unacked = &unackedRequest{gen: gen, ch: ch, seq: seq, deadline: deadline}
				return ctx.Err()
			case <-c.closing:
				t.Stop()
				return knx.ErrClosed
			}
		}
	}
	err := fmt.Errorf("%w: tunnel: no TUNNELLING_ACK for sequence %d on channel %d", knx.ErrConnectionLost, seq, ch)
	c.signalLost(gen, err)
	return err
}

// settle ends the exchange of a request whose caller left before its
// acknowledgement arrived. It waits for that TUNNELLING_ACK until the
// request timeout of the request has passed and then lets the sequence
// counter advance, so that the next request does not carry the number of
// a frame the server may have taken. The request is not repeated: its
// caller gave it up. Without the acknowledgement the connection is lost,
// as for any request that is not acknowledged, and stays so for every
// later call until it is closed or reconnected. The caller holds the send
// turn.
func (c *Conn) settle(ctx context.Context) error {
	p := c.unacked
	if p == nil {
		return nil
	}
	c.mu.Lock()
	current := c.gen == p.gen && c.state == knx.StateConnected
	c.mu.Unlock()
	if !current {
		// The connection the request was sent on is gone, and its
		// sequence counter with it.
		c.unacked = nil
		return nil
	}
	if !p.lost {
		acked := func(ack *knxnetip.TunnellingAck) bool {
			if ack.Channel != p.ch || ack.Seq != p.seq {
				return false // a late ACK of an earlier request
			}
			c.unacked = nil
			if ack.Status == knxnetip.StatusNoError {
				c.advance(p.gen)
			}
			return true
		}
		// The acknowledgement that came while nobody waited is kept.
		select {
		case ack := <-c.ackCh:
			if acked(ack) {
				return nil
			}
		default:
		}
		t := time.NewTimer(time.Until(p.deadline))
		defer t.Stop()
	wait:
		for {
			select {
			case ack := <-c.ackCh:
				if acked(ack) {
					return nil
				}
			case <-t.C:
				break wait
			case <-ctx.Done():
				return ctx.Err()
			case <-c.closing:
				return knx.ErrClosed
			}
		}
		p.lost = true
	}
	err := fmt.Errorf("%w: tunnel: no TUNNELLING_ACK for sequence %d on channel %d", knx.ErrConnectionLost, p.seq, p.ch)
	c.signalLost(p.gen, err)
	return err
}

// sendError maps a failed write of Send to the error contract: after
// Close an error matching knx.ErrClosed; when the connection was lost (the
// socket closed under Send, or the write itself failed) one matching
// knx.ErrConnectionLost. Both wrap the write error. A failed write on a
// connection that is still up counts as losing it, except a frame that
// could not be encoded (knx.ErrInvalidValue), which is returned as is.
func (c *Conn) sendError(gen uint64, err error) error {
	if errors.Is(err, knx.ErrInvalidValue) {
		// The frame could not be encoded (e.g. too long once secured):
		// nothing was sent and the connection is fine.
		return err
	}
	select {
	case <-c.closing:
		c.mu.Lock()
		cause := c.err
		c.mu.Unlock()
		if cause == nil {
			return fmt.Errorf("%w: tunnel: send: %w", knx.ErrClosed, err)
		}
		if errors.Is(cause, knx.ErrConnectionLost) {
			return fmt.Errorf("%w: send: %w", cause, err)
		}
		return fmt.Errorf("%w: tunnel: %w: send: %w", knx.ErrConnectionLost, cause, err)
	default:
	}
	lost := fmt.Errorf("%w: tunnel: send: %w", knx.ErrConnectionLost, err)
	c.signalLost(gen, lost)
	return lost
}

// Receive returns the next frame the server sent on the tunnel
// (L_Data.ind, L_Busmon.ind...), excluding the L_Data.con of this
// client's own requests. It returns knx.ErrClosed, or the error the
// connection was lost with, once the Conn is closed and the queue empty.
func (c *Conn) Receive(ctx context.Context) (cemi.Frame, error) {
	select {
	case f := <-c.inbound:
		return f, nil
	default:
	}
	select {
	case f := <-c.inbound:
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		select {
		case f := <-c.inbound:
			return f, nil
		default:
		}
		if err := c.Err(); err != nil {
			return nil, err
		}
		return nil, knx.ErrClosed
	}
}

func (c *Conn) signalLost(gen uint64, err error) {
	select {
	case c.lost <- lostEvent{gen: gen, err: err}:
	default:
	}
}

// readLoop reads and dispatches every datagram until the socket closes.
func (c *Conn) readLoop() {
	defer c.wg.Done()
	buf := make([]byte, knxnetip.MaxFrameLen+1)
	for {
		n, from, err := c.tr.readFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if c.tr.stream() {
				// The TCP connection is gone (or carried garbage): the
				// tunnel cannot continue on it.
				select {
				case <-c.closing:
				default:
					c.mu.Lock()
					gen := c.gen
					c.mu.Unlock()
					c.signalLost(gen, fmt.Errorf("%w: %v", knx.ErrConnectionLost, err))
				}
				return
			}
			c.o.logger.Warnf("tunnel: read: %v", err)
			continue
		}
		fromAddr := net.UDPAddrFromAddrPort(from)
		m, err := knxnetip.Parse(buf[:n])
		if err != nil {
			c.o.metrics.OnDecodeError(fromAddr, err)
			c.o.logger.Debugf("tunnel: drop datagram from %s: %v", from, err)
			continue
		}
		c.o.metrics.OnFrameReceived(fromAddr, uint16(m.Service()), n)
		if !c.fromServer(from) {
			c.o.metrics.OnDropped(fromAddr, "foreign_source")
			continue
		}
		c.dispatch(from, m)
	}
}

// fromServer accepts datagrams from the server's address only. The port
// may differ between control and data endpoints.
func (c *Conn) fromServer(from netip.AddrPort) bool {
	if c.tr.stream() || from.Addr() == c.server.Addr() {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return from.Addr() == c.dataEP.Addr()
}

func (c *Conn) dispatch(from netip.AddrPort, m knxnetip.Message) {
	switch m := m.(type) {
	case *knxnetip.ConnectResponse:
		offer(c.connCh, m)
	case *knxnetip.TunnellingFeature:
		// Feature frames of the server use the sequence counter of
		// tunnelling requests (and, over UDP, their ACKs).
		if !c.acceptSeq(from, m.Channel, m.Seq) {
			return
		}
		switch m.Type {
		case knxnetip.TunnellingFeatureResponseType, knxnetip.TunnellingFeatureInfoType:
			offer(c.featCh, m)
		default:
			// A client does not answer GET or SET.
		}
	case *knxnetip.TunnellingAck:
		offer(c.ackCh, m)
	case *knxnetip.ConnectionStateResponse:
		offer(c.csCh, m)
	case *knxnetip.DisconnectResponse:
		offer(c.discCh, m)
	case *knxnetip.DeviceConfigurationAck:
		offer(c.ackCh, &knxnetip.TunnellingAck{Channel: m.Channel, Seq: m.Seq, Status: m.Status})
	case *knxnetip.DeviceConfigurationRequest:
		if c.o.devmgmt {
			c.onRequest(from, &knxnetip.TunnellingRequest{Channel: m.Channel, Seq: m.Seq, CEMI: m.CEMI})
		}
	case *knxnetip.TunnellingRequest:
		c.onRequest(from, m)
	case *knxnetip.DisconnectRequest:
		c.mu.Lock()
		ch, gen, state := c.channel, c.gen, c.state
		c.mu.Unlock()
		to := c.server
		if !c.o.nat && !m.Control.IsRouteBack() {
			to = m.Control.Addr
		}
		if m.Channel != ch {
			// Not our channel: answer E_CONNECTION_ID and keep the tunnel
			// (Core, disconnect of an unknown communication channel).
			_ = c.write(to, &knxnetip.DisconnectResponse{Channel: m.Channel, Status: knxnetip.StatusConnectionID})
			return
		}
		if state != knx.StateConnected {
			return
		}
		_ = c.write(to, &knxnetip.DisconnectResponse{Channel: ch, Status: knxnetip.StatusNoError})
		c.mu.Lock()
		if c.gen == gen {
			c.remoteClosed = true
		}
		c.mu.Unlock()
		c.signalLost(gen, fmt.Errorf("%w: tunnel: the server disconnected channel %d", knx.ErrConnectionLost, ch))
	default:
		c.o.logger.Debugf("tunnel: ignore %s from %s", m.Service(), from)
	}
}

func offer[T any](ch chan T, v T) {
	select {
	case ch <- v:
	default:
		// The waiter is gone or busy: replace a stale value.
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- v:
		default:
		}
	}
}

// acceptSeq applies the receiver side of the sequence counter to a frame
// of the server (acknowledging it over UDP) and reports whether it is new.
func (c *Conn) acceptSeq(from netip.AddrPort, ch, seq uint8) bool {
	c.mu.Lock()
	cur, state, dataEP := c.channel, c.state, c.dataEP
	expected := c.rxSeq
	stream := c.tr.stream()
	deliver, ack := false, false
	switch {
	case ch != cur || state != knx.StateConnected:
	case stream:
		c.rxSeq = seq + 1
		deliver = true
	case seq == expected:
		c.rxSeq++
		deliver, ack = true, true
	case seq == expected-1:
		ack = true
	}
	c.mu.Unlock()
	if ack {
		to := dataEP
		if c.o.nat {
			to = from
		}
		_ = c.write(to, &knxnetip.TunnellingAck{Channel: cur, Seq: seq, Status: knxnetip.StatusNoError})
	}
	return deliver
}

// onRequest implements the receiver side of the sequence counter: the
// expected sequence number is acknowledged and delivered; the previous one
// (a repetition whose ACK was lost) is acknowledged and dropped; any other
// is dropped without an ACK.
func (c *Conn) onRequest(from netip.AddrPort, m *knxnetip.TunnellingRequest) {
	c.mu.Lock()
	ch, state, dataEP := c.channel, c.state, c.dataEP
	expected := c.rxSeq
	deliver, ack := false, false
	stream := c.tr.stream()
	switch {
	case m.Channel != ch || state != knx.StateConnected:
	case stream:
		// TCP delivers in order and without repetitions.
		c.rxSeq = m.Seq + 1
		deliver, ack = true, true
	case m.Seq == expected:
		c.rxSeq++
		deliver, ack = true, true
	case m.Seq == expected-1:
		ack = true
	}
	c.mu.Unlock()
	fromAddr := net.UDPAddrFromAddrPort(from)
	if !ack {
		c.o.metrics.OnDropped(fromAddr, "sequence")
		c.o.logger.Debugf("tunnel: drop request channel %d sequence %d (expected %d)", m.Channel, m.Seq, expected)
		return
	}
	to := dataEP
	if c.o.nat {
		to = from
	}
	if !stream {
		if c.o.devmgmt {
			_ = c.write(to, &knxnetip.DeviceConfigurationAck{Channel: ch, Seq: m.Seq, Status: knxnetip.StatusNoError})
		} else {
			_ = c.write(to, &knxnetip.TunnellingAck{Channel: ch, Seq: m.Seq, Status: knxnetip.StatusNoError})
		}
	}
	if !deliver {
		c.o.metrics.OnDropped(fromAddr, "duplicate")
		return
	}
	f, err := cemi.Parse(m.CEMI)
	if err != nil {
		c.o.metrics.OnDecodeError(fromAddr, err)
		c.o.logger.Debugf("tunnel: drop cEMI from %s: %v", from, err)
		return
	}
	if ld, ok := f.(*cemi.LData); ok && ld.MsgCode == cemi.LDataCon {
		c.conMu.Lock()
		w := c.conWait
		if w != nil && w.dst == ld.Destination && w.group == ld.IsGroup() && bytes.Equal(w.tpdu, ld.TPDU) {
			c.conWait = nil
			w.ch <- ld
			c.conMu.Unlock()
			return
		}
		c.conMu.Unlock()
	}
	select {
	case c.inbound <- f:
	default:
		c.o.metrics.OnDropped(fromAddr, "queue_full")
		c.o.logger.Warnf("tunnel: inbound queue full, telegram dropped")
	}
}

// heartbeatLoop sends CONNECTIONSTATE_REQUESTs.
func (c *Conn) heartbeatLoop() {
	defer c.wg.Done()
	t := time.NewTicker(c.o.heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-c.closing:
			return
		case <-t.C:
		}
		c.mu.Lock()
		state, ch, gen := c.state, c.channel, c.gen
		c.mu.Unlock()
		if state != knx.StateConnected {
			continue
		}
		if err := c.heartbeat(ch); err != nil {
			c.signalLost(gen, err)
		}
	}
}

func (c *Conn) heartbeat(ch uint8) error {
	drain(c.csCh)
	for i := 0; i < c.o.heartbeatAttempts; i++ {
		if err := c.write(c.server, &knxnetip.ConnectionStateRequest{Channel: ch, Control: c.hpai}); err != nil {
			return err
		}
		t := time.NewTimer(c.o.heartbeatTimeout)
		select {
		case r := <-c.csCh:
			t.Stop()
			if r.Channel != ch {
				continue
			}
			if r.Status != knxnetip.StatusNoError {
				return fmt.Errorf("%w: tunnel: CONNECTIONSTATE_RESPONSE %s", knx.ErrConnectionLost, r.Status)
			}
			return nil
		case <-t.C:
		case <-c.closing:
			t.Stop()
			return knx.ErrClosed
		}
	}
	return fmt.Errorf("%w: tunnel: no CONNECTIONSTATE_RESPONSE after %d attempts", knx.ErrConnectionLost, c.o.heartbeatAttempts)
}

// supervise handles lost connections: reconnect or close. Each reconnect
// runs under a child of parent that Close cancels.
func (c *Conn) supervise(parent context.Context) {
	defer c.wg.Done()
	defer close(c.superDone)
	for {
		var ev lostEvent
		select {
		case <-c.stopping:
			return
		case ev = <-c.lost:
		}
		c.mu.Lock()
		stale := ev.gen != c.gen
		ch, remoteClosed := c.channel, c.remoteClosed
		c.mu.Unlock()
		if stale {
			continue
		}
		c.o.metrics.OnDisconnect(net.UDPAddrFromAddrPort(c.server), ch, ev.err)
		c.o.logger.Warnf("tunnel: connection lost: %v", ev.err)
		if !c.o.reconnect {
			go c.shutdown(ev.err)
			return
		}
		// Tell the server, in case it still holds the channel.
		if !remoteClosed {
			_ = c.write(c.server, &knxnetip.DisconnectRequest{Channel: ch, Control: c.hpai})
		}
		c.setState(knx.StateReconnecting, ev.err)
		// Each wait is a random time in the upper half of the backoff:
		// clients that lost the same server do not all come back at once.
		pause := c.o.reconnectMin
		for {
			select {
			case <-c.stopping:
				return
			case <-time.After(backoff.Jitter(pause, c.o.jitter)):
			}
			ctx, cancel := context.WithCancel(parent)
			go func() {
				select {
				case <-c.stopping:
					cancel()
				case <-ctx.Done():
				}
			}()
			err := c.connect(ctx)
			cancel()
			if err == nil {
				drain(c.lost)
				break
			}
			if errors.Is(err, knx.ErrClosed) {
				return
			}
			c.o.logger.Debugf("tunnel: reconnect: %v", err)
			if pause *= 2; pause > c.o.reconnectMax {
				pause = c.o.reconnectMax
			}
		}
	}
}

// Close disconnects (DISCONNECT_REQUEST, waiting briefly for the
// response), stops the goroutines and closes the socket. During a
// reconnection it waits up to a second for the answer to the
// CONNECT_REQUEST in flight and disconnects the channel that answer
// opened. It is safe to call more than once.
func (c *Conn) Close() error {
	c.shutdown(nil)
	return nil
}

// closeWriteTimeout bounds each write of Close (DISCONNECT_REQUEST, the
// SESSION_STATUS close of a secure session).
const closeWriteTimeout = time.Second

func (c *Conn) shutdown(cause error) {
	c.closeMu.Do(func() {
		// The supervisor ends first: a reconnection it runs disconnects
		// the channel the server opens for it, and one that completed
		// is disconnected here.
		close(c.stopping)
		if c.superDone != nil {
			<-c.superDone
		}
		c.mu.Lock()
		state, ch, remoteClosed := c.state, c.channel, c.remoteClosed
		if cause != nil {
			c.err = cause
		}
		c.mu.Unlock()
		if state == knx.StateConnected && !remoteClosed {
			drain(c.discCh)
			// A server that does not read does not hold up Close: the
			// DISCONNECT_REQUEST gets at most closeWriteTimeout.
			ctx, cancel := context.WithTimeout(context.Background(), closeWriteTimeout)
			err := c.writeContext(ctx, c.server, &knxnetip.DisconnectRequest{Channel: ch, Control: c.hpai})
			cancel()
			if err == nil {
				t := time.NewTimer(time.Second)
				select {
				case <-c.discCh:
				case <-t.C:
				}
				t.Stop()
			}
			if cause == nil {
				c.o.metrics.OnDisconnect(net.UDPAddrFromAddrPort(c.server), ch, nil)
			}
		}
		close(c.closing)
		_ = c.tr.close()
		c.wg.Wait()
		c.setState(knx.StateClosed, cause)
		close(c.done)
	})
	<-c.done
}
