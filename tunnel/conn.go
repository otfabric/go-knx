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
// the Conn is closed. A Conn is safe for concurrent use; sends are
// serialised, as tunnelling allows one unacknowledged request at a time.
package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/udp"
	"github.com/otfabric/go-knx/knxnetip"
)

// Conn is a KNXnet/IP tunnelling connection.
type Conn struct {
	o      options
	sock   *net.UDPConn
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

	sendMu sync.Mutex
	ackCh  chan *knxnetip.TunnellingAck
	connCh chan *knxnetip.ConnectResponse
	csCh   chan *knxnetip.ConnectionStateResponse
	discCh chan *knxnetip.DisconnectResponse

	conMu   sync.Mutex
	conWait *confirmWait

	inbound chan cemi.Frame
	lost    chan lostEvent
	closing chan struct{}
	done    chan struct{}
	closeMu sync.Once
	wg      sync.WaitGroup
}

type lostEvent struct {
	gen uint64
	err error
}

type confirmWait struct {
	dst   uint16
	group bool
	tpdu  []byte
	ch    chan *cemi.LData
}

// Dial connects to the KNXnet/IP server at addr ("192.168.1.10",
// "192.168.1.10:3671") and establishes a tunnelling connection.
func Dial(ctx context.Context, addr string, opts ...Option) (*Conn, error) {
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
	sock, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, fmt.Errorf("tunnel: listen %s: %w", local, err)
	}
	c := &Conn{
		o: o, sock: sock, server: server,
		ackCh:   make(chan *knxnetip.TunnellingAck, 1),
		connCh:  make(chan *knxnetip.ConnectResponse, 1),
		csCh:    make(chan *knxnetip.ConnectionStateResponse, 1),
		discCh:  make(chan *knxnetip.DisconnectResponse, 1),
		inbound: make(chan cemi.Frame, o.queueSize),
		lost:    make(chan lostEvent, 1),
		closing: make(chan struct{}),
		done:    make(chan struct{}),
	}
	if o.nat {
		c.hpai = knxnetip.RouteBackHPAI()
	} else {
		bound := udp.AddrPortOf(sock.LocalAddr())
		ip := bound.Addr()
		if !ip.IsValid() || ip.IsUnspecified() {
			if ip, err = udp.LocalIPFor(server); err != nil {
				sock.Close()
				return nil, fmt.Errorf("tunnel: no route to %s: %w", server, err)
			}
		}
		c.hpai = knxnetip.NewHPAI(netip.AddrPortFrom(ip, bound.Port()))
	}
	c.setState(knx.StateConnecting, nil)
	c.wg.Add(1)
	go c.readLoop()
	if err := c.connect(ctx); err != nil {
		c.shutdown(err)
		return nil, err
	}
	c.wg.Add(2)
	go c.heartbeatLoop()
	go c.supervise()
	return c, nil
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
func (c *Conn) LocalAddr() net.Addr { return c.sock.LocalAddr() }

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
	b, err := knxnetip.Marshal(m)
	if err != nil {
		return err
	}
	if _, err := c.sock.WriteToUDPAddrPort(b, to); err != nil {
		return fmt.Errorf("tunnel: write %s to %s: %w", m.Service(), to, err)
	}
	c.o.metrics.OnFrameSent(net.UDPAddrFromAddrPort(to), uint16(m.Service()), len(b))
	return nil
}

// connect performs CONNECT_REQUEST / CONNECT_RESPONSE.
func (c *Conn) connect(ctx context.Context) error {
	drain(c.connCh)
	cri := knxnetip.TunnelCRI(c.o.layer)
	if c.o.hasAddress {
		cri.HasAddress, cri.Address = true, c.o.address
	}
	req := &knxnetip.ConnectRequest{Control: c.hpai, Data: c.hpai, CRI: cri}
	if err := c.write(c.server, req); err != nil {
		return err
	}
	t := time.NewTimer(c.o.connectTimeout)
	defer t.Stop()
	select {
	case resp := <-c.connCh:
		if resp.Status != knxnetip.StatusNoError {
			return &knxnetip.StatusError{Service: knxnetip.ConnectResponseType, Status: resp.Status}
		}
		if resp.CRD.Type != knxnetip.TunnelConnection {
			return fmt.Errorf("%w: tunnel: CONNECT_RESPONSE with a %s CRD", knx.ErrMalformed, resp.CRD.Type)
		}
		data := resp.Data.Addr
		if c.o.nat || resp.Data.IsRouteBack() {
			data = c.server
		}
		c.mu.Lock()
		c.channel, c.dataEP, c.addr = resp.Channel, data, resp.CRD.Address
		c.rxSeq, c.txSeq = 0, 0
		c.gen++
		c.mu.Unlock()
		c.setState(knx.StateConnected, nil)
		c.o.metrics.OnConnect(net.UDPAddrFromAddrPort(c.server), resp.Channel)
		c.o.logger.Infof("tunnel: connected to %s, channel %d, address %s", c.server, resp.Channel, resp.CRD.Address)
		return nil
	case <-t.C:
		return fmt.Errorf("%w: tunnel: no CONNECT_RESPONSE from %s within %v", knx.ErrTimeout, c.server, c.o.connectTimeout)
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closing:
		return knx.ErrClosed
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
func (c *Conn) Send(ctx context.Context, f cemi.Frame) error {
	b, err := cemi.Marshal(f)
	if err != nil {
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
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

	drain(c.ackCh)
	req := &knxnetip.TunnellingRequest{Channel: ch, Seq: seq, CEMI: b}
	acked := false
	for attempt := 0; attempt < 2 && !acked; attempt++ {
		if attempt > 0 {
			c.o.metrics.OnRetransmit(net.UDPAddrFromAddrPort(dataEP), ch)
			c.o.logger.Debugf("tunnel: no ACK for sequence %d, repeating", seq)
		}
		if err := c.write(dataEP, req); err != nil {
			return err
		}
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
				acked = true
				break wait
			case <-t.C:
				break wait
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-c.closing:
				t.Stop()
				return knx.ErrClosed
			}
		}
	}
	if !acked {
		err := fmt.Errorf("%w: tunnel: no TUNNELLING_ACK for sequence %d on channel %d", knx.ErrConnectionLost, seq, ch)
		c.signalLost(gen, err)
		return err
	}
	c.mu.Lock()
	if c.gen == gen {
		c.txSeq++
	}
	c.mu.Unlock()

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
		n, from, err := c.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.o.logger.Warnf("tunnel: read: %v", err)
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
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
	if from.Addr() == c.server.Addr() {
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
	case *knxnetip.TunnellingAck:
		offer(c.ackCh, m)
	case *knxnetip.ConnectionStateResponse:
		offer(c.csCh, m)
	case *knxnetip.DisconnectResponse:
		offer(c.discCh, m)
	case *knxnetip.TunnellingRequest:
		c.onRequest(from, m)
	case *knxnetip.DisconnectRequest:
		c.mu.Lock()
		ch, gen, state := c.channel, c.gen, c.state
		c.mu.Unlock()
		if m.Channel != ch || state != knx.StateConnected {
			return
		}
		to := c.server
		if !c.o.nat && !m.Control.IsRouteBack() {
			to = m.Control.Addr
		}
		_ = c.write(to, &knxnetip.DisconnectResponse{Channel: ch, Status: knxnetip.StatusNoError})
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

// onRequest implements the receiver side of the sequence counter: the
// expected sequence number is acknowledged and delivered; the previous one
// (a repetition whose ACK was lost) is acknowledged and dropped; any other
// is dropped without an ACK.
func (c *Conn) onRequest(from netip.AddrPort, m *knxnetip.TunnellingRequest) {
	c.mu.Lock()
	ch, state, dataEP := c.channel, c.state, c.dataEP
	expected := c.rxSeq
	deliver, ack := false, false
	switch {
	case m.Channel != ch || state != knx.StateConnected:
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
	_ = c.write(to, &knxnetip.TunnellingAck{Channel: ch, Seq: m.Seq, Status: knxnetip.StatusNoError})
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

// supervise handles lost connections: reconnect or close.
func (c *Conn) supervise() {
	defer c.wg.Done()
	for {
		var ev lostEvent
		select {
		case <-c.closing:
			return
		case ev = <-c.lost:
		}
		c.mu.Lock()
		stale := ev.gen != c.gen
		ch := c.channel
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
		_ = c.write(c.server, &knxnetip.DisconnectRequest{Channel: ch, Control: c.hpai})
		c.setState(knx.StateReconnecting, ev.err)
		backoff := c.o.reconnectMin
		for {
			select {
			case <-c.closing:
				return
			case <-time.After(backoff):
			}
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				select {
				case <-c.closing:
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
			if backoff *= 2; backoff > c.o.reconnectMax {
				backoff = c.o.reconnectMax
			}
		}
	}
}

// Close disconnects (DISCONNECT_REQUEST, waiting briefly for the
// response), stops the goroutines and closes the socket. It is safe to
// call more than once.
func (c *Conn) Close() error {
	c.shutdown(nil)
	return nil
}

func (c *Conn) shutdown(cause error) {
	c.closeMu.Do(func() {
		c.mu.Lock()
		state, ch := c.state, c.channel
		if cause != nil {
			c.err = cause
		}
		c.mu.Unlock()
		if state == knx.StateConnected {
			drain(c.discCh)
			if err := c.write(c.server, &knxnetip.DisconnectRequest{Channel: ch, Control: c.hpai}); err == nil {
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
		_ = c.sock.Close()
		c.wg.Wait()
		c.setState(knx.StateClosed, cause)
		close(c.done)
	})
	<-c.done
}
