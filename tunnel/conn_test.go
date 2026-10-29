// SPDX-License-Identifier: MIT

package tunnel_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/tunnel"
)

const wait = 2 * time.Second

var (
	tunnelAddr = knx.MustParseIndividualAddress("1.1.200")
	group      = knx.MustParseGroupAddress("1/2/3")
)

// metrics records the callbacks the tests look at.
type metrics struct {
	knx.NopMetrics
	mu          sync.Mutex
	retransmits int
	dropped     map[string]int
	decode      int
	connects    int
	disconnects []error
}

func newMetrics() *metrics { return &metrics{dropped: map[string]int{}} }

func (m *metrics) OnRetransmit(net.Addr, uint8) { m.mu.Lock(); m.retransmits++; m.mu.Unlock() }
func (m *metrics) OnDropped(_ net.Addr, r string) {
	m.mu.Lock()
	m.dropped[r]++
	m.mu.Unlock()
}
func (m *metrics) OnDecodeError(net.Addr, error) { m.mu.Lock(); m.decode++; m.mu.Unlock() }
func (m *metrics) OnConnect(net.Addr, uint8)     { m.mu.Lock(); m.connects++; m.mu.Unlock() }
func (m *metrics) OnDisconnect(_ net.Addr, _ uint8, err error) {
	m.mu.Lock()
	m.disconnects = append(m.disconnects, err)
	m.mu.Unlock()
}

func (m *metrics) get(f func(m *metrics) int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return f(m)
}

// eventually polls cond until it holds or fails the test.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

type fixture struct {
	t       *testing.T
	p       *fakeknx.Peer
	c       *tunnel.Conn
	m       *metrics
	ch      uint8
	client  netip.AddrPort // the client's data endpoint
	connReq *knxnetip.ConnectRequest
}

func baseOpts(m *metrics) []tunnel.Option {
	return []tunnel.Option{
		tunnel.WithMetrics(m),
		tunnel.WithConnectTimeout(wait),
		tunnel.WithRequestTimeout(100 * time.Millisecond),
		tunnel.WithConfirm(true, 300*time.Millisecond),
	}
}

// dial connects a Conn to a fake server that accepts on channel 7.
func dial(t *testing.T, opts ...tunnel.Option) *fixture {
	t.Helper()
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	return dialPeer(t, p, opts...)
}

func dialPeer(t *testing.T, p *fakeknx.Peer, opts ...tunnel.Option) *fixture {
	t.Helper()
	f := &fixture{t: t, p: p, m: newMetrics(), ch: 7}
	type result struct {
		c   *tunnel.Conn
		err error
	}
	res := make(chan result, 1)
	go func() {
		c, err := tunnel.Dial(context.Background(), p.String(), append(baseOpts(f.m), opts...)...)
		res <- result{c, err}
	}()
	req, d := fakeknx.Expect[*knxnetip.ConnectRequest](p, wait)
	f.connReq = req
	f.client = req.Data.Addr
	if req.Data.IsRouteBack() {
		f.client = d.From
	}
	ctrl := req.Control.Addr
	if req.Control.IsRouteBack() {
		ctrl = d.From
	}
	p.Send(ctrl, &knxnetip.ConnectResponse{Channel: f.ch, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
	r := <-res
	if r.err != nil {
		t.Fatal(r.err)
	}
	f.c = r.c
	t.Cleanup(func() { f.c.Close() })
	return f
}

func groupWrite(v byte) *cemi.LData {
	tpdu, err := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{v}})
	if err != nil {
		panic(err)
	}
	return cemi.NewGroupFrame(cemi.LDataReq, 0, group, knx.PriorityLow, tpdu)
}

func indication(v byte) []byte {
	f := groupWrite(v)
	f.MsgCode = cemi.LDataInd
	f.Source = knx.MustParseIndividualAddress("1.1.5")
	b, err := cemi.Marshal(f)
	if err != nil {
		panic(err)
	}
	return b
}

// send runs Send in the background.
func (f *fixture) send(fr cemi.Frame) <-chan error {
	return f.sendCtx(context.Background(), fr)
}

func (f *fixture) sendCtx(c context.Context, fr cemi.Frame) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- f.c.Send(c, fr) }()
	return ch
}

func (f *fixture) expectRequest() *knxnetip.TunnellingRequest {
	f.t.Helper()
	req, _ := fakeknx.Expect[*knxnetip.TunnellingRequest](f.p, wait)
	if req.Channel != f.ch {
		f.t.Fatalf("request on channel %d, want %d", req.Channel, f.ch)
	}
	return req
}

func (f *fixture) ack(seq uint8, st knxnetip.Status) {
	f.p.Send(f.client, &knxnetip.TunnellingAck{Channel: f.ch, Seq: seq, Status: st})
}

// confirm sends the L_Data.con of req as server request seq.
func (f *fixture) confirm(req *knxnetip.TunnellingRequest, seq uint8, failed bool) {
	f.p.Send(f.client, &knxnetip.TunnellingRequest{Channel: f.ch, Seq: seq, CEMI: fakeknx.Confirmation(req.CEMI, failed)})
}

func (f *fixture) inbound(seq uint8, cemiFrame []byte) {
	f.p.Send(f.client, &knxnetip.TunnellingRequest{Channel: f.ch, Seq: seq, CEMI: cemiFrame})
}

func result(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(wait):
		t.Fatal("Send did not return")
		return nil
	}
}

func pending(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		t.Fatalf("Send returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func receive(t *testing.T, c *tunnel.Conn) cemi.Frame {
	t.Helper()
	cx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	f, err := c.Receive(cx)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDial(t *testing.T) {
	leak.Check(t)
	var mu sync.Mutex
	var states []knx.State
	f := dial(t, tunnel.WithStateHandler(func(s knx.State, _ error) {
		mu.Lock()
		states = append(states, s)
		mu.Unlock()
	}))
	if f.c.Channel() != 7 || f.c.IndividualAddress() != tunnelAddr || f.c.State() != knx.StateConnected {
		t.Fatalf("channel %d address %s state %s", f.c.Channel(), f.c.IndividualAddress(), f.c.State())
	}
	if f.c.Server() != f.p.Addr() {
		t.Fatalf("server %s", f.c.Server())
	}
	if f.connReq.Control.IsRouteBack() || f.connReq.Control.Addr.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("control HPAI %s", f.connReq.Control)
	}
	if lp := f.c.LocalAddr().(*net.UDPAddr).Port; int(f.connReq.Data.Addr.Port()) != lp {
		t.Fatalf("data HPAI %s, socket port %d", f.connReq.Data, lp)
	}
	if f.connReq.CRI.Type != knxnetip.TunnelConnection || f.connReq.CRI.Layer != knxnetip.TunnelLinkLayer || f.connReq.CRI.HasAddress {
		t.Fatalf("CRI %+v", f.connReq.CRI)
	}
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.c.Done():
	default:
		t.Fatal("Done not closed after Close")
	}
	if f.c.Err() != nil || f.c.State() != knx.StateClosed {
		t.Fatalf("after Close: err %v state %s", f.c.Err(), f.c.State())
	}
	mu.Lock()
	defer mu.Unlock()
	want := []knx.State{knx.StateConnecting, knx.StateConnected, knx.StateClosed}
	if len(states) != len(want) {
		t.Fatalf("states %v, want %v", states, want)
	}
	for i := range want {
		if states[i] != want[i] {
			t.Fatalf("states %v, want %v", states, want)
		}
	}
	if f.m.get(func(m *metrics) int { return m.connects }) != 1 || f.m.get(func(m *metrics) int { return len(m.disconnects) }) != 1 {
		t.Fatalf("metrics %+v", f.m)
	}
}

func TestCloseSendsDisconnect(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	f := dialPeer(t, p)
	done := make(chan struct{})
	go func() { f.c.Close(); close(done) }()
	req, d := fakeknx.Expect[*knxnetip.DisconnectRequest](p, wait)
	if req.Channel != 7 {
		t.Fatalf("disconnect channel %d", req.Channel)
	}
	p.Send(d.From, &knxnetip.DisconnectResponse{Channel: 7})
	select {
	case <-done:
	case <-time.After(wait):
		t.Fatal("Close did not return")
	}
	// Idempotent.
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Send(ctx(t), groupWrite(1)); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
	if _, err := f.c.Receive(ctx(t)); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("Receive after Close: %v", err)
	}
}

func TestCloseWithoutDisconnectResponse(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	f := dialPeer(t, p)
	start := time.Now()
	f.c.Close()
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("Close took %v", d)
	}
	fakeknx.Expect[*knxnetip.DisconnectRequest](p, wait)
}

func TestDialRefused(t *testing.T) {
	leak.Check(t)
	for _, st := range []knxnetip.Status{
		knxnetip.StatusNoMoreConnections, knxnetip.StatusNoMoreUniqueConns, knxnetip.StatusConnectionType,
		knxnetip.StatusConnectionOption, knxnetip.StatusTunnellingLayer, knxnetip.StatusNoTunnellingAddress,
		knxnetip.StatusConnectionInUse, knxnetip.StatusHostProtocolType, knxnetip.StatusAuthorisationError,
	} {
		t.Run(st.String(), func(t *testing.T) {
			p := fakeknx.Listen(t)
			p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
				if _, ok := d.Msg.(*knxnetip.ConnectRequest); ok {
					p.Send(d.From, &knxnetip.ConnectResponse{Status: st})
					return true
				}
				return false
			})
			_, err := tunnel.Dial(ctx(t), p.String(), tunnel.WithConnectTimeout(wait))
			if !errors.Is(err, knx.ErrRejected) {
				t.Fatalf("err %v, want ErrRejected", err)
			}
			if got, ok := knxnetip.StatusOf(err); !ok || got != st {
				t.Fatalf("status %v %v", got, ok)
			}
			busy := st == knxnetip.StatusNoMoreConnections || st == knxnetip.StatusNoMoreUniqueConns
			if errors.Is(err, knx.ErrBusy) != busy {
				t.Fatalf("ErrBusy match %t for %s", !busy, st)
			}
		})
	}
}

func TestDialWrongCRD(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if _, ok := d.Msg.(*knxnetip.ConnectRequest); ok {
			p.Send(d.From, &knxnetip.ConnectResponse{Channel: 1, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.DeviceManagementConnection}})
			return true
		}
		return false
	})
	if _, err := tunnel.Dial(ctx(t), p.String()); !errors.Is(err, knx.ErrMalformed) {
		t.Fatalf("err %v", err)
	}
}

func TestDialTimeout(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	start := time.Now()
	_, err := tunnel.Dial(ctx(t), p.String(), tunnel.WithConnectTimeout(100*time.Millisecond))
	if !errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("err %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}

func TestDialContextCanceled(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	c, cancel := context.WithCancel(context.Background())
	go func() {
		fakeknx.Expect[*knxnetip.ConnectRequest](p, wait)
		cancel()
	}()
	if _, err := tunnel.Dial(c, p.String()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

func TestDialErrors(t *testing.T) {
	leak.Check(t)
	for name, tc := range map[string]struct {
		addr string
		opts []tunnel.Option
	}{
		"layer":             {"127.0.0.1:1", []tunnel.Option{tunnel.WithLayer(knxnetip.TunnelRaw)}},
		"request timeout":   {"127.0.0.1:1", []tunnel.Option{tunnel.WithRequestTimeout(0)}},
		"connect timeout":   {"127.0.0.1:1", []tunnel.Option{tunnel.WithConnectTimeout(-1)}},
		"heartbeat":         {"127.0.0.1:1", []tunnel.Option{tunnel.WithHeartbeat(time.Second, time.Second, 0)}},
		"heartbeat timeout": {"127.0.0.1:1", []tunnel.Option{tunnel.WithHeartbeat(time.Second, 0, 1)}},
		"confirm":           {"127.0.0.1:1", []tunnel.Option{tunnel.WithConfirm(true, 0)}},
		"queue":             {"127.0.0.1:1", []tunnel.Option{tunnel.WithQueueSize(0)}},
		"queue max":         {"127.0.0.1:1", []tunnel.Option{tunnel.WithQueueSize(1<<16 + 1)}},
		"reconnect":         {"127.0.0.1:1", []tunnel.Option{tunnel.WithReconnect(time.Second, time.Millisecond)}},
		"reconnect zero":    {"127.0.0.1:1", []tunnel.Option{tunnel.WithReconnect(0, time.Second)}},
		"address":           {"[::1]:3671", nil},
		"port":              {"127.0.0.1:x", nil},
		"local":             {"127.0.0.1:1", []tunnel.Option{tunnel.WithLocalAddr("127.0.0.1:x")}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tunnel.Dial(ctx(t), tc.addr, tc.opts...); !errors.Is(err, knx.ErrInvalidOption) {
				t.Fatalf("err %v, want ErrInvalidOption", err)
			}
		})
	}
	// A local address that cannot be bound.
	if _, err := tunnel.Dial(ctx(t), "127.0.0.1:1", tunnel.WithLocalAddr("192.0.2.1:0")); err == nil {
		t.Fatal("bind to a foreign address succeeded")
	}
}

func TestOptions(t *testing.T) {
	leak.Check(t)
	// Nil logger and metrics fall back to the defaults; the busmonitor
	// layer and an individual address go into the CRI.
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	f := dialPeer(t, p, tunnel.WithLogger(nil), tunnel.WithLayer(knxnetip.TunnelBusmonitor),
		tunnel.WithIndividualAddress(tunnelAddr), tunnel.WithLocalAddr("127.0.0.1"), tunnel.WithLogger(knx.NopLogger()))
	cri := f.connReq.CRI
	if cri.Layer != knxnetip.TunnelBusmonitor || !cri.HasAddress || cri.Address != tunnelAddr {
		t.Fatalf("CRI %+v", cri)
	}
	if f.connReq.Control.Addr.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("control %s", f.connReq.Control)
	}
	c, err := tunnel.Dial(ctx(t), "127.0.0.1:1", tunnel.WithMetrics(nil), tunnel.WithConnectTimeout(10*time.Millisecond))
	if err == nil {
		c.Close()
		t.Fatal("dial of a closed port succeeded")
	}
}

func TestSendAckAndConfirm(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	for seq := uint8(0); seq < 3; seq++ {
		res := f.send(groupWrite(seq))
		req := f.expectRequest()
		if req.Seq != seq {
			t.Fatalf("sequence %d, want %d", req.Seq, seq)
		}
		f.ack(seq, knxnetip.StatusNoError)
		pending(t, res) // waits for the L_Data.con
		f.confirm(req, seq, false)
		if err := result(t, res); err != nil {
			t.Fatal(err)
		}
		if a, _ := fakeknx.Expect[*knxnetip.TunnellingAck](f.p, wait); a.Seq != seq {
			t.Fatalf("ack of the confirmation: sequence %d", a.Seq)
		}
	}
	// The confirmations were consumed, not delivered.
	c, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if fr, err := f.c.Receive(c); err == nil {
		t.Fatalf("confirmation delivered: %v", fr)
	}
}

func TestSendConfirmError(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	res := f.send(groupWrite(1))
	req := f.expectRequest()
	f.ack(req.Seq, knxnetip.StatusNoError)
	f.confirm(req, 0, true)
	if err := result(t, res); !errors.Is(err, knx.ErrNotConfirmed) {
		t.Fatalf("err %v", err)
	}
}

func TestSendConfirmMissing(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	res := f.send(groupWrite(1))
	req := f.expectRequest()
	f.ack(req.Seq, knxnetip.StatusNoError)
	// A confirmation of another telegram does not match and is delivered.
	other := groupWrite(9)
	ob, _ := cemi.Marshal(other)
	f.confirm(&knxnetip.TunnellingRequest{CEMI: ob}, 0, false)
	if err := result(t, res); !errors.Is(err, knx.ErrNotConfirmed) {
		t.Fatalf("err %v", err)
	}
	fr := receive(t, f.c)
	if ld, ok := fr.(*cemi.LData); !ok || ld.MsgCode != cemi.LDataCon || !bytes.Equal(ld.TPDU, other.TPDU) {
		t.Fatalf("delivered %v", fr)
	}
	// The connection is still usable.
	res = f.send(groupWrite(2))
	req = f.expectRequest()
	if req.Seq != 1 {
		t.Fatalf("sequence %d", req.Seq)
	}
	f.ack(1, knxnetip.StatusNoError)
	f.confirm(req, 1, false)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
}

func TestSendWithoutConfirm(t *testing.T) {
	leak.Check(t)
	f := dial(t, tunnel.WithConfirm(false, 0))
	res := f.send(groupWrite(1))
	req := f.expectRequest()
	f.ack(req.Seq, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
	// Non-L_Data frames are not confirmed either.
	f2 := dial(t)
	ind := groupWrite(1)
	ind.MsgCode = cemi.LDataInd
	res = f2.send(ind)
	req = f2.expectRequest()
	f2.ack(req.Seq, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
}

func TestSendInvalidFrame(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	bad := groupWrite(1)
	bad.TPDU = nil
	if err := f.c.Send(ctx(t), bad); err == nil {
		t.Fatal("Send of a frame without TPDU succeeded")
	}
}

func TestSendRetransmit(t *testing.T) {
	leak.Check(t)
	f := dial(t, tunnel.WithConfirm(false, 0))
	res := f.send(groupWrite(1))
	first := f.expectRequest()
	second := f.expectRequest()
	if first.Seq != second.Seq || !bytes.Equal(first.CEMI, second.CEMI) {
		t.Fatalf("repetition differs: %+v %+v", first, second)
	}
	f.ack(second.Seq, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
	if n := f.m.get(func(m *metrics) int { return m.retransmits }); n != 1 {
		t.Fatalf("retransmits %d", n)
	}
	if f.c.State() != knx.StateConnected {
		t.Fatalf("state %s", f.c.State())
	}
}

func TestSendNoAckLosesConnection(t *testing.T) {
	leak.Check(t)
	f := dial(t, tunnel.WithConfirm(false, 0))
	res := f.send(groupWrite(1))
	f.expectRequest()
	f.expectRequest()
	if err := result(t, res); !errors.Is(err, knx.ErrConnectionLost) {
		t.Fatalf("err %v", err)
	}
	select {
	case <-f.c.Done():
	case <-time.After(wait):
		t.Fatal("Done not closed")
	}
	if !errors.Is(f.c.Err(), knx.ErrConnectionLost) {
		t.Fatalf("Err %v", f.c.Err())
	}
	if _, err := f.c.Receive(ctx(t)); !errors.Is(err, knx.ErrConnectionLost) {
		t.Fatalf("Receive: %v", err)
	}
	if err := f.c.Send(ctx(t), groupWrite(2)); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("Send after loss: %v", err)
	}
	if n := f.m.get(func(m *metrics) int { return len(m.disconnects) }); n != 1 {
		t.Fatalf("disconnect metrics %d", n)
	}
}

func TestSendAckError(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	res := f.send(groupWrite(1))
	req := f.expectRequest()
	f.ack(req.Seq, knxnetip.StatusSequenceNumber)
	err := result(t, res)
	if st, ok := knxnetip.StatusOf(err); !ok || st != knxnetip.StatusSequenceNumber || !errors.Is(err, knx.ErrRejected) {
		t.Fatalf("err %v", err)
	}
	// The sequence number is not consumed by a refused request.
	res = f.send(groupWrite(2))
	if req = f.expectRequest(); req.Seq != 0 {
		t.Fatalf("sequence %d after a refused request", req.Seq)
	}
	f.ack(0, knxnetip.StatusNoError)
	f.confirm(req, 0, false)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
}

func TestLateAndDuplicateAcks(t *testing.T) {
	leak.Check(t)
	f := dial(t, tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(time.Second))
	res := f.send(groupWrite(1))
	req := f.expectRequest()
	// Acks of another sequence number or channel do not complete it.
	f.ack(req.Seq+5, knxnetip.StatusNoError)
	f.p.Send(f.client, &knxnetip.TunnellingAck{Channel: f.ch + 1, Seq: req.Seq})
	pending(t, res)
	f.ack(req.Seq, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
	// A duplicate of that ack does not complete the next request.
	f.ack(req.Seq, knxnetip.StatusNoError)
	res = f.send(groupWrite(2))
	next := f.expectRequest()
	if next.Seq != req.Seq+1 {
		t.Fatalf("sequence %d", next.Seq)
	}
	pending(t, res)
	f.ack(next.Seq, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
	if n := f.m.get(func(m *metrics) int { return m.retransmits }); n != 0 {
		t.Fatalf("retransmits %d", n)
	}
}

func TestInboundSequence(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	expectAck := func(seq uint8) {
		t.Helper()
		a, _ := fakeknx.Expect[*knxnetip.TunnellingAck](f.p, wait)
		if a.Seq != seq || a.Channel != f.ch || a.Status != knxnetip.StatusNoError {
			t.Fatalf("ack %+v, want sequence %d", a, seq)
		}
	}
	f.inbound(0, indication(10))
	expectAck(0)
	if ld := receive(t, f.c).(*cemi.LData); ld.TPDU[len(ld.TPDU)-1] != 10 {
		t.Fatalf("frame %v", ld)
	}
	f.inbound(0, indication(11)) // repetition: acked, dropped
	expectAck(0)
	f.inbound(5, indication(12))                                                                     // out of order: no ack
	f.p.Send(f.client, &knxnetip.TunnellingRequest{Channel: f.ch + 1, Seq: 1, CEMI: indication(13)}) // other channel
	f.inbound(1, indication(14))
	expectAck(1) // the first ack after the duplicate's: 5 and the other channel got none
	if ld := receive(t, f.c).(*cemi.LData); ld.TPDU[len(ld.TPDU)-1] != 14 {
		t.Fatalf("frame %v", ld)
	}
	eventually(t, "drop metrics", func() bool {
		return f.m.get(func(m *metrics) int { return m.dropped["duplicate"] }) == 1 &&
			f.m.get(func(m *metrics) int { return m.dropped["sequence"] }) == 2
	})
	// Undecodable cEMI is acknowledged and counted.
	f.inbound(2, []byte{0x29, 0x00})
	expectAck(2)
	eventually(t, "decode error", func() bool { return f.m.get(func(m *metrics) int { return m.decode }) == 1 })
	// Undecodable datagrams are counted.
	f.p.SendRaw(f.client, []byte{0x06, 0x10, 0x04, 0x20, 0x00})
	eventually(t, "decode error", func() bool { return f.m.get(func(m *metrics) int { return m.decode }) == 2 })
}

func TestSequenceRollover(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	var mu sync.Mutex
	var seqs []uint8
	f := dialPeer(t, p, tunnel.WithConfirm(false, 0))
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if r, ok := d.Msg.(*knxnetip.TunnellingRequest); ok {
			mu.Lock()
			seqs = append(seqs, r.Seq)
			mu.Unlock()
			p.Send(d.From, &knxnetip.TunnellingAck{Channel: r.Channel, Seq: r.Seq})
			return true
		}
		return false
	})
	const n = 300
	for i := 0; i < n; i++ {
		if err := f.c.Send(ctx(t), groupWrite(byte(i))); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	mu.Lock()
	for i, s := range seqs {
		if s != uint8(i) {
			mu.Unlock()
			t.Fatalf("send %d had sequence %d", i, s)
		}
	}
	mu.Unlock()
	// Inbound: the counter wraps too.
	for i := 0; i < n; i++ {
		f.inbound(uint8(i), indication(byte(i)))
		a, _ := fakeknx.Expect[*knxnetip.TunnellingAck](p, wait)
		if a.Seq != uint8(i) {
			t.Fatalf("inbound %d acked as %d", i, a.Seq)
		}
		if ld := receive(t, f.c).(*cemi.LData); ld.TPDU[len(ld.TPDU)-1] != byte(i) {
			t.Fatalf("inbound %d: %v", i, ld)
		}
	}
	// After the wrap, 255 is the repetition of the last one before 0.
	last := uint8(n - 1 - 256)
	f.inbound(last, indication(0))
	if a, _ := fakeknx.Expect[*knxnetip.TunnellingAck](p, wait); a.Seq != last {
		t.Fatalf("duplicate acked as %d", a.Seq)
	}
	eventually(t, "duplicate", func() bool { return f.m.get(func(m *metrics) int { return m.dropped["duplicate"] }) == 1 })
}

func TestQueueFull(t *testing.T) {
	leak.Check(t)
	f := dial(t, tunnel.WithQueueSize(1))
	for seq := uint8(0); seq < 3; seq++ {
		f.inbound(seq, indication(seq))
		if a, _ := fakeknx.Expect[*knxnetip.TunnellingAck](f.p, wait); a.Seq != seq {
			t.Fatalf("ack %d", a.Seq)
		}
	}
	eventually(t, "queue_full", func() bool { return f.m.get(func(m *metrics) int { return m.dropped["queue_full"] }) == 2 })
	if ld := receive(t, f.c).(*cemi.LData); ld.TPDU[len(ld.TPDU)-1] != 0 {
		t.Fatalf("frame %v", ld)
	}
}

func TestReceiveDrainsAfterClose(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	f.inbound(0, indication(1))
	fakeknx.Expect[*knxnetip.TunnellingAck](f.p, wait)
	f.c.Close()
	fr, err := f.c.Receive(ctx(t))
	if err != nil {
		t.Fatalf("queued frame lost: %v", err)
	}
	if _, ok := fr.(*cemi.LData); !ok {
		t.Fatalf("frame %v", fr)
	}
	if _, err := f.c.Receive(ctx(t)); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("err %v", err)
	}
}

func TestReceiveBlocksUntilFrame(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	got := make(chan cemi.Frame, 1)
	go func() {
		fr, err := f.c.Receive(context.Background())
		if err == nil {
			got <- fr
		}
		close(got)
	}()
	f.inbound(0, indication(3))
	select {
	case fr := <-got:
		if fr == nil {
			t.Fatal("no frame")
		}
	case <-time.After(wait):
		t.Fatal("Receive did not return")
	}
}

func TestHeartbeat(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	var mu sync.Mutex
	count := 0
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if m, ok := d.Msg.(*knxnetip.ConnectionStateRequest); ok {
			mu.Lock()
			count++
			mu.Unlock()
			if m.Control.IsRouteBack() {
				t.Errorf("heartbeat with route back HPAI")
			}
			p.Send(m.Control.Addr, &knxnetip.ConnectionStateResponse{Channel: m.Channel})
			return true
		}
		return false
	})
	f := dialPeer(t, p, tunnel.WithHeartbeat(20*time.Millisecond, 200*time.Millisecond, 1))
	eventually(t, "heartbeats", func() bool { mu.Lock(); defer mu.Unlock(); return count >= 5 })
	if f.c.State() != knx.StateConnected || f.c.Err() != nil {
		t.Fatalf("state %s err %v", f.c.State(), f.c.Err())
	}
}

func TestHeartbeatFailure(t *testing.T) {
	leak.Check(t)
	for name, answer := range map[string]func(p *fakeknx.Peer, d fakeknx.Datagram, m *knxnetip.ConnectionStateRequest){
		"no response": nil,
		"status error": func(p *fakeknx.Peer, d fakeknx.Datagram, m *knxnetip.ConnectionStateRequest) {
			p.Send(d.From, &knxnetip.ConnectionStateResponse{Channel: m.Channel, Status: knxnetip.StatusConnectionID})
		},
		"wrong channel": func(p *fakeknx.Peer, d fakeknx.Datagram, m *knxnetip.ConnectionStateRequest) {
			p.Send(d.From, &knxnetip.ConnectionStateResponse{Channel: m.Channel + 1})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := fakeknx.Listen(t)
			p.Handle(fakeknx.AnswerDisconnect)
			var mu sync.Mutex
			attempts := 0
			p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
				if m, ok := d.Msg.(*knxnetip.ConnectionStateRequest); ok {
					mu.Lock()
					attempts++
					mu.Unlock()
					if answer != nil {
						answer(p, d, m)
					}
					return true
				}
				return false
			})
			f := dialPeer(t, p, tunnel.WithHeartbeat(20*time.Millisecond, 30*time.Millisecond, 2))
			select {
			case <-f.c.Done():
			case <-time.After(wait):
				t.Fatal("connection not lost")
			}
			if !errors.Is(f.c.Err(), knx.ErrConnectionLost) {
				t.Fatalf("Err %v", f.c.Err())
			}
			mu.Lock()
			defer mu.Unlock()
			// The heartbeat goroutine may start another round while the
			// Conn shuts down.
			if name != "status error" && attempts < 2 {
				t.Fatalf("%d attempts, want at least 2", attempts)
			}
		})
	}
}

func TestServerDisconnect(t *testing.T) {
	leak.Check(t)
	f := dial(t)
	// Another channel's disconnect is ignored.
	f.p.Send(f.client, &knxnetip.DisconnectRequest{Channel: f.ch + 1, Control: f.p.HPAI()})
	f.p.Send(f.client, &knxnetip.DisconnectRequest{Channel: f.ch, Control: f.p.HPAI()})
	resp, _ := fakeknx.Expect[*knxnetip.DisconnectResponse](f.p, wait)
	if resp.Channel != f.ch || resp.Status != knxnetip.StatusNoError {
		t.Fatalf("response %+v", resp)
	}
	select {
	case <-f.c.Done():
	case <-time.After(wait):
		t.Fatal("not closed")
	}
	if !errors.Is(f.c.Err(), knx.ErrConnectionLost) {
		t.Fatalf("Err %v", f.c.Err())
	}
	// The channel is gone: the client does not disconnect it again.
	fakeknx.ExpectNone[*knxnetip.DisconnectRequest](f.p, 50*time.Millisecond)
}

func TestReconnect(t *testing.T) {
	leak.Check(t)
	var mu sync.Mutex
	var states []knx.State
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	f := dialPeer(t, p, tunnel.WithReconnect(10*time.Millisecond, 20*time.Millisecond), tunnel.WithConfirm(false, 0),
		tunnel.WithStateHandler(func(s knx.State, _ error) {
			mu.Lock()
			states = append(states, s)
			mu.Unlock()
		}))
	f.p.Send(f.client, &knxnetip.DisconnectRequest{Channel: f.ch, Control: f.p.HPAI()})
	fakeknx.Expect[*knxnetip.DisconnectResponse](p, wait)

	// The first reconnection is refused, the second accepted.
	req, d := fakeknx.Expect[*knxnetip.ConnectRequest](p, wait)
	if f.c.State() != knx.StateReconnecting {
		t.Fatalf("state %s while reconnecting", f.c.State())
	}
	if err := f.c.Send(ctx(t), groupWrite(1)); !errors.Is(err, knx.ErrConnectionLost) {
		t.Fatalf("Send while reconnecting: %v", err)
	}
	p.Send(req.Control.Addr, &knxnetip.ConnectResponse{Status: knxnetip.StatusNoMoreConnections})
	_ = d
	req, _ = fakeknx.Expect[*knxnetip.ConnectRequest](p, wait)
	p.Send(req.Control.Addr, &knxnetip.ConnectResponse{Channel: 8, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
	eventually(t, "reconnected", func() bool { return f.c.State() == knx.StateConnected })
	if f.c.Channel() != 8 {
		t.Fatalf("channel %d", f.c.Channel())
	}
	f.ch = 8
	res := f.send(groupWrite(2))
	if r := f.expectRequest(); r.Seq != 0 {
		t.Fatalf("sequence %d after reconnection", r.Seq)
	}
	f.ack(0, knxnetip.StatusNoError)
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}

	// A heartbeat-less loss: no ack. The client disconnects the old
	// channel and reconnects.
	res = f.send(groupWrite(3))
	f.expectRequest()
	f.expectRequest()
	if err := result(t, res); !errors.Is(err, knx.ErrConnectionLost) {
		t.Fatalf("err %v", err)
	}
	req, _ = fakeknx.Expect[*knxnetip.ConnectRequest](p, wait)
	p.Send(req.Control.Addr, &knxnetip.ConnectResponse{Channel: 9, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
	eventually(t, "reconnected", func() bool { return f.c.State() == knx.StateConnected && f.c.Channel() == 9 })

	f.c.Close()
	mu.Lock()
	defer mu.Unlock()
	want := []knx.State{knx.StateConnecting, knx.StateConnected, knx.StateReconnecting, knx.StateConnected,
		knx.StateReconnecting, knx.StateConnected, knx.StateClosed}
	if len(states) != len(want) {
		t.Fatalf("states %v, want %v", states, want)
	}
	for i := range want {
		if states[i] != want[i] {
			t.Fatalf("states %v, want %v", states, want)
		}
	}
}

func TestCloseWhileReconnecting(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	f := dialPeer(t, p, tunnel.WithReconnect(10*time.Millisecond, 10*time.Millisecond), tunnel.WithConnectTimeout(time.Minute))
	f.p.Send(f.client, &knxnetip.DisconnectRequest{Channel: f.ch, Control: f.p.HPAI()})
	fakeknx.Expect[*knxnetip.ConnectRequest](p, wait) // never answered
	done := make(chan struct{})
	go func() { f.c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(wait):
		t.Fatal("Close blocked while reconnecting")
	}
	if f.c.State() != knx.StateClosed {
		t.Fatalf("state %s", f.c.State())
	}
}

func TestNAT(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	hb := make(chan *knxnetip.ConnectionStateRequest, 4)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if m, ok := d.Msg.(*knxnetip.ConnectionStateRequest); ok {
			select {
			case hb <- m:
			default:
			}
			p.Send(d.From, &knxnetip.ConnectionStateResponse{Channel: m.Channel})
			return true
		}
		return false
	})
	f := dialPeer(t, p, tunnel.WithNAT(true), tunnel.WithConfirm(false, 0), tunnel.WithHeartbeat(20*time.Millisecond, time.Second, 1))
	if !f.connReq.Control.IsRouteBack() || !f.connReq.Data.IsRouteBack() {
		t.Fatalf("CONNECT_REQUEST HPAIs %s %s, want 0.0.0.0:0", f.connReq.Control, f.connReq.Data)
	}
	select {
	case m := <-hb:
		if !m.Control.IsRouteBack() {
			t.Fatalf("heartbeat HPAI %s", m.Control)
		}
	case <-time.After(wait):
		t.Fatal("no heartbeat")
	}
	res := f.send(groupWrite(1))
	_, d := fakeknx.Expect[*knxnetip.TunnellingRequest](p, wait)
	p.Send(d.From, &knxnetip.TunnellingAck{Channel: f.ch, Seq: 0})
	if err := result(t, res); err != nil {
		t.Fatal(err)
	}
	f.inbound(0, indication(1))
	if a, _ := fakeknx.Expect[*knxnetip.TunnellingAck](p, wait); a.Seq != 0 {
		t.Fatalf("ack %+v", a)
	}
	// A server disconnect is answered to the datagram's source.
	f.p.Send(f.client, &knxnetip.DisconnectRequest{Channel: f.ch, Control: knxnetip.RouteBackHPAI()})
	fakeknx.Expect[*knxnetip.DisconnectResponse](p, wait)
	<-f.c.Done()
}

// TestSeparateDataEndpoint: the server's data endpoint differs from its
// control endpoint; requests go there, control services to the control
// endpoint.
func TestSeparateDataEndpoint(t *testing.T) {
	leak.Check(t)
	ctrl := fakeknx.Listen(t)
	ctrl.Handle(fakeknx.AnswerDisconnect)
	data := fakeknx.Listen(t)
	m := newMetrics()
	res := make(chan *tunnel.Conn, 1)
	go func() {
		c, err := tunnel.Dial(context.Background(), ctrl.String(), append(baseOpts(m), tunnel.WithConfirm(false, 0))...)
		if err != nil {
			t.Error(err)
		}
		res <- c
	}()
	req, _ := fakeknx.Expect[*knxnetip.ConnectRequest](ctrl, wait)
	ctrl.Send(req.Control.Addr, &knxnetip.ConnectResponse{Channel: 3, Data: data.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
	c := <-res
	if c == nil {
		return
	}
	defer c.Close()
	sent := make(chan error, 1)
	go func() { sent <- c.Send(ctx(t), groupWrite(1)) }()
	r, d := fakeknx.Expect[*knxnetip.TunnellingRequest](data, wait)
	data.Send(d.From, &knxnetip.TunnellingAck{Channel: 3, Seq: r.Seq})
	if err := result(t, sent); err != nil {
		t.Fatal(err)
	}
	// Inbound requests from the data endpoint are acknowledged to it.
	data.Send(req.Data.Addr, &knxnetip.TunnellingRequest{Channel: 3, Seq: 0, CEMI: indication(1)})
	fakeknx.Expect[*knxnetip.TunnellingAck](data, wait)

	// A CONNECT_RESPONSE with a route back data endpoint uses the
	// control endpoint.
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	go func() {
		c, err := tunnel.Dial(context.Background(), p.String(), append(baseOpts(m), tunnel.WithConfirm(false, 0))...)
		if err != nil {
			t.Error(err)
		}
		res <- c
	}()
	req, _ = fakeknx.Expect[*knxnetip.ConnectRequest](p, wait)
	p.Send(req.Control.Addr, &knxnetip.ConnectResponse{Channel: 4, Data: knxnetip.RouteBackHPAI(), CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
	c2 := <-res
	if c2 == nil {
		return
	}
	defer c2.Close()
	go func() { sent <- c2.Send(ctx(t), groupWrite(1)) }()
	r, d = fakeknx.Expect[*knxnetip.TunnellingRequest](p, wait)
	p.Send(d.From, &knxnetip.TunnellingAck{Channel: 4, Seq: r.Seq})
	if err := result(t, sent); err != nil {
		t.Fatal(err)
	}
}

func TestForeignSourceDropped(t *testing.T) {
	leak.Check(t)
	ip := nonLoopbackIPv4(t)
	f := dial(t)
	foreign := fakeknx.ListenAddr(t, netip.AddrPortFrom(ip, 0).String())
	to := netip.AddrPortFrom(ip, uint16(f.c.LocalAddr().(*net.UDPAddr).Port))
	foreign.Send(to, &knxnetip.TunnellingRequest{Channel: f.ch, Seq: 0, CEMI: indication(1)})
	eventually(t, "foreign_source drop", func() bool { return f.m.get(func(m *metrics) int { return m.dropped["foreign_source"] }) == 1 })
	if _, ok := foreign.Next(30 * time.Millisecond); ok {
		t.Fatal("foreign request answered")
	}
	// The expected sequence number is still 0.
	f.inbound(0, indication(2))
	if a, _ := fakeknx.Expect[*knxnetip.TunnellingAck](f.p, wait); a.Seq != 0 {
		t.Fatalf("ack %d", a.Seq)
	}
}

func nonLoopbackIPv4(t *testing.T) netip.Addr {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() && !ip.Unmap().IsLinkLocalUnicast() {
					c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: n.IP})
					if err != nil {
						continue
					}
					c.Close()
					return ip.Unmap()
				}
			}
		}
	}
	t.Skip("no non-loopback IPv4 address to send from")
	return netip.Addr{}
}

func TestContextCancel(t *testing.T) {
	leak.Check(t)
	f := dial(t, tunnel.WithRequestTimeout(time.Minute))
	c, cancel := context.WithCancel(context.Background())
	res := f.sendCtx(c, groupWrite(1))
	f.expectRequest()
	cancel()
	if err := result(t, res); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send: %v", err)
	}
	// Canceled while waiting for the confirmation.
	c, cancel = context.WithCancel(context.Background())
	res = f.sendCtx(c, groupWrite(2))
	req := f.expectRequest()
	f.ack(req.Seq, knxnetip.StatusNoError)
	pending(t, res)
	cancel()
	if err := result(t, res); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send: %v", err)
	}
	// Receive.
	c, cancel = context.WithCancel(context.Background())
	got := make(chan error, 1)
	go func() { _, err := f.c.Receive(c); got <- err }()
	cancel()
	if err := result(t, got); !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive: %v", err)
	}
}

func TestCloseDuringSend(t *testing.T) {
	leak.Check(t)
	f := dial(t, tunnel.WithRequestTimeout(time.Minute))
	res := f.send(groupWrite(1))
	f.expectRequest()
	f.c.Close()
	if err := result(t, res); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("Send: %v", err)
	}
	// Close while waiting for the confirmation.
	f = dial(t, tunnel.WithConfirm(true, time.Minute))
	res = f.send(groupWrite(1))
	req := f.expectRequest()
	f.ack(req.Seq, knxnetip.StatusNoError)
	pending(t, res)
	f.c.Close()
	if err := result(t, res); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("Send: %v", err)
	}
}

func TestConcurrentSends(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	f := dialPeer(t, p)
	// An automatic server: ack, then confirm, with its own sequence.
	var mu sync.Mutex
	var srvSeq uint8
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		r, ok := d.Msg.(*knxnetip.TunnellingRequest)
		if !ok {
			_, isAck := d.Msg.(*knxnetip.TunnellingAck)
			return isAck
		}
		p.Send(d.From, &knxnetip.TunnellingAck{Channel: r.Channel, Seq: r.Seq})
		mu.Lock()
		s := srvSeq
		srvSeq++
		mu.Unlock()
		p.Send(d.From, &knxnetip.TunnellingRequest{Channel: r.Channel, Seq: s, CEMI: fakeknx.Confirmation(r.CEMI, false)})
		return true
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := f.c.Send(context.Background(), groupWrite(byte(i*20+j))); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
