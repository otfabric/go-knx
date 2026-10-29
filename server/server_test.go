// SPDX-License-Identifier: MIT

package server_test

import (
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
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

func TestSearchAndDescribe(t *testing.T) {
	leak.Check(t)
	s, _ := start(t, server.WithName("test server"), server.WithSerial([6]byte{0, 1, 2, 3, 4, 5}),
		server.WithMAC([6]byte{2, 0, 0, 0, 0, 9}), server.WithIndividualAddress(knx.MustParseIndividualAddress("1.1.0")))
	p := fakeknx.Listen(t)

	p.Send(s.Addr(), &knxnetip.SearchRequest{Discovery: p.HPAI()})
	resp, _ := fakeknx.Expect[*knxnetip.SearchResponse](p, wait)
	if resp.Extended || resp.Control.Addr != s.Addr() {
		t.Fatalf("response %+v", resp)
	}
	d, ok := resp.DIBs.DeviceInfo()
	if !ok || d.Name != "test server" || d.Serial != [6]byte{0, 1, 2, 3, 4, 5} || d.MAC != [6]byte{2, 0, 0, 0, 0, 9} ||
		d.Address != knx.MustParseIndividualAddress("1.1.0") || d.ProgrammingMode() || d.Multicast != netip.IPv4Unspecified() {
		t.Fatalf("device info %+v", d)
	}
	fam, _ := resp.DIBs.SupportedServices()
	if v, ok := fam.Version(knxnetip.FamilyTunnelling); !ok || v != 2 {
		t.Fatalf("families %+v", fam)
	}
	if v, ok := fam.Version(knxnetip.FamilyDeviceManagement); !ok || v != 1 {
		t.Fatalf("families %+v", fam)
	}
	if _, ok := fam.Version(knxnetip.FamilyRouting); ok {
		t.Fatal("routing announced without routing")
	}

	// Route back: answered to the source.
	p.Send(s.Addr(), &knxnetip.SearchRequest{Discovery: knxnetip.RouteBackHPAI()})
	fakeknx.Expect[*knxnetip.SearchResponse](p, wait)

	// TCP: no answer.
	p.Send(s.Addr(), &knxnetip.SearchRequest{Discovery: knxnetip.TCPHPAI()})
	p.Send(s.Addr(), &knxnetip.SearchRequestExt{Discovery: knxnetip.TCPHPAI()})
	p.Send(s.Addr(), &knxnetip.DescriptionRequest{Control: p.HPAI()})
	x, ok := p.Next(wait)
	if !ok {
		t.Fatal("no description response")
	}
	dr, ok := x.Msg.(*knxnetip.DescriptionResponse)
	if !ok {
		t.Fatalf("got %s, want DESCRIPTION_RESPONSE (TCP search answered?)", x.Msg.Service())
	}
	if d, _ := dr.DIBs.DeviceInfo(); d.Name != "test server" {
		t.Fatalf("description %+v", dr.DIBs)
	}
}

func TestSearchExtended(t *testing.T) {
	leak.Check(t)
	mac := [6]byte{2, 0, 0, 0, 0, 9}
	p := fakeknx.Listen(t)
	type tc struct {
		prog   bool
		params []knxnetip.SearchParam
		answer bool
		check  func(t *testing.T, ds knxnetip.DIBs)
	}
	has := func(types ...knxnetip.DIBType) func(t *testing.T, ds knxnetip.DIBs) {
		return func(t *testing.T, ds knxnetip.DIBs) {
			t.Helper()
			if len(ds) != len(types) {
				t.Fatalf("DIBs %+v, want types %v", ds, types)
			}
			for i, want := range types {
				if ds[i].Type() != want {
					t.Fatalf("DIB %d is %s, want %s", i, ds[i].Type(), want)
				}
			}
		}
	}
	for name, c := range map[string]tc{
		"no params":           {answer: true, check: has(knxnetip.DIBDeviceInfo, knxnetip.DIBSupportedServices, knxnetip.DIBExtendedDeviceInfo)},
		"prog mode off":       {params: []knxnetip.SearchParam{{Type: knxnetip.SRPProgrammingMode}}},
		"prog mode on":        {prog: true, params: []knxnetip.SearchParam{{Type: knxnetip.SRPProgrammingMode}}, answer: true},
		"mac match":           {params: []knxnetip.SearchParam{{Type: knxnetip.SRPMACAddress, Data: mac[:]}}, answer: true},
		"mac mismatch":        {params: []knxnetip.SearchParam{{Type: knxnetip.SRPMACAddress, Data: []byte{2, 0, 0, 0, 0, 8}}}},
		"mac short":           {params: []knxnetip.SearchParam{{Type: knxnetip.SRPMACAddress, Data: mac[:5]}}},
		"service ok":          {params: []knxnetip.SearchParam{{Type: knxnetip.SRPService, Data: []byte{byte(knxnetip.FamilyTunnelling), 1}}}, answer: true},
		"service version":     {params: []knxnetip.SearchParam{{Type: knxnetip.SRPService, Data: []byte{byte(knxnetip.FamilyTunnelling), 3}}}},
		"service missing":     {params: []knxnetip.SearchParam{{Type: knxnetip.SRPService, Data: []byte{byte(knxnetip.FamilyRouting), 1}}}},
		"service bad length":  {params: []knxnetip.SearchParam{{Type: knxnetip.SRPService, Data: []byte{4}}}},
		"unknown mandatory":   {params: []knxnetip.SearchParam{{Type: 0x33, Mandatory: true}}},
		"unknown optional":    {params: []knxnetip.SearchParam{{Type: 0x33}}, answer: true},
		"invalid (mandatory)": {params: []knxnetip.SearchParam{{Type: knxnetip.SRPInvalid, Mandatory: true}}},
		"request DIBs": {params: []knxnetip.SearchParam{{Type: knxnetip.SRPRequestDIBs, Data: []byte{
			byte(knxnetip.DIBTunnellingInfo), byte(knxnetip.DIBKNXAddresses), byte(knxnetip.DIBDeviceInfo),
			byte(knxnetip.DIBExtendedDeviceInfo), byte(knxnetip.DIBSupportedServices), byte(knxnetip.DIBManufacturerData), 0}}},
			answer: true,
			check: has(knxnetip.DIBDeviceInfo, knxnetip.DIBSupportedServices, knxnetip.DIBTunnellingInfo,
				knxnetip.DIBKNXAddresses, knxnetip.DIBExtendedDeviceInfo)},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := start(t, server.WithMAC(mac), server.WithProgrammingMode(c.prog))
			p.Send(s.Addr(), &knxnetip.SearchRequestExt{Discovery: p.HPAI(), Params: c.params})
			// A description request after it: the server handles datagrams
			// in order, so a missing search answer shows as the
			// description coming first.
			p.Send(s.Addr(), &knxnetip.DescriptionRequest{Control: p.HPAI()})
			x, ok := p.Next(wait)
			if !ok {
				t.Fatal("no answer at all")
			}
			resp, isSearch := x.Msg.(*knxnetip.SearchResponse)
			if isSearch != c.answer {
				t.Fatalf("answered %t, want %t (%s)", isSearch, c.answer, x.Msg.Service())
			}
			if !isSearch {
				return
			}
			fakeknx.Expect[*knxnetip.DescriptionResponse](p, wait)
			if !resp.Extended {
				t.Fatal("not a SEARCH_RESPONSE_EXTENDED")
			}
			if d, _ := resp.DIBs.DeviceInfo(); d.ProgrammingMode() != c.prog {
				t.Fatalf("programming mode %t", d.ProgrammingMode())
			}
			if c.check != nil {
				c.check(t, resp.DIBs)
			}
		})
	}
}

func TestTunnellingInfo(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	dialRaw(t, s)
	p := fakeknx.Listen(t)
	p.Send(s.Addr(), &knxnetip.SearchRequestExt{Discovery: p.HPAI(), Params: []knxnetip.SearchParam{
		{Type: knxnetip.SRPRequestDIBs, Data: []byte{byte(knxnetip.DIBTunnellingInfo), byte(knxnetip.DIBKNXAddresses)}}}})
	resp, _ := fakeknx.Expect[*knxnetip.SearchResponse](p, wait)
	d, ok := resp.DIBs.Find(knxnetip.DIBTunnellingInfo)
	if !ok {
		t.Fatal("no TUNNELLING_INFO")
	}
	ti := d.(knxnetip.TunnellingInfo)
	if len(ti.Slots) != 2 || ti.Slots[0].Address != slot1 || ti.Slots[0].Free() || !ti.Slots[1].Free() {
		t.Fatalf("slots %+v", ti.Slots)
	}
	d, _ = resp.DIBs.Find(knxnetip.DIBKNXAddresses)
	if ka := d.(knxnetip.KNXAddresses); len(ka.Addresses) != 3 || ka.Addresses[0] != serverAddr {
		t.Fatalf("addresses %+v", ka)
	}
}

func TestConnectRefusals(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	link := knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)
	withAddr := func(a knx.IndividualAddress) knxnetip.CRI {
		c := link
		c.HasAddress, c.Address = true, a
		return c
	}
	try := func(ctrl, data knxnetip.HPAI, cri knxnetip.CRI) knxnetip.Status {
		t.Helper()
		p := fakeknx.Listen(t)
		if ctrl.Protocol == knxnetip.IPv4UDP && !ctrl.IsRouteBack() {
			ctrl = p.HPAI()
		}
		p.Send(s.Addr(), &knxnetip.ConnectRequest{Control: ctrl, Data: data, CRI: cri})
		resp, _ := fakeknx.Expect[*knxnetip.ConnectResponse](p, wait)
		return resp.Status
	}
	udp := knxnetip.NewHPAI(netip.MustParseAddrPort("127.0.0.1:1"))
	for name, c := range map[string]struct {
		ctrl, data knxnetip.HPAI
		cri        knxnetip.CRI
		want       knxnetip.Status
	}{
		"TCP data":        {udp, knxnetip.TCPHPAI(), link, knxnetip.StatusHostProtocolType},
		"remote config":   {udp, udp, knxnetip.CRI{Type: knxnetip.RemoteConfigConnection}, knxnetip.StatusConnectionType},
		"raw":             {udp, udp, knxnetip.TunnelCRI(knxnetip.TunnelRaw), knxnetip.StatusTunnellingLayer},
		"unknown address": {udp, udp, withAddr(knx.MustParseIndividualAddress("9.9.9")), knxnetip.StatusNoTunnellingAddress},
	} {
		if got := try(c.ctrl, c.data, c.cri); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	// TCP control endpoint: the refusal goes to the datagram source.
	p := fakeknx.Listen(t)
	p.Send(s.Addr(), &knxnetip.ConnectRequest{Control: knxnetip.TCPHPAI(), Data: knxnetip.TCPHPAI(), CRI: link})
	if resp, _ := fakeknx.Expect[*knxnetip.ConnectResponse](p, wait); resp.Status != knxnetip.StatusHostProtocolType {
		t.Fatalf("TCP: %s", resp.Status)
	}

	// An address in use, then exhaustion.
	a := newRaw(t, s)
	if resp := a.connect(withAddr(slot2)); resp.Status != knxnetip.StatusNoError || resp.CRD.Address != slot2 {
		t.Fatalf("connect to %s: %+v", slot2, resp)
	}
	if got := try(udp, udp, withAddr(slot2)); got != knxnetip.StatusConnectionInUse {
		t.Fatalf("in use: %s", got)
	}
	b := dialRaw(t, s)
	if b.addr != slot1 || b.ch == a.ch {
		t.Fatalf("second connection %s channel %d (first %d)", b.addr, b.ch, a.ch)
	}
	if got := try(udp, udp, link); got != knxnetip.StatusNoMoreConnections {
		t.Fatalf("exhausted: %s", got)
	}
	if _, err := tunnel.Dial(ctx(t), s.Addr().String()); !errors.Is(err, knx.ErrBusy) {
		t.Fatalf("tunnel.Dial when exhausted: %v", err)
	}
	if n := len(s.Connections()); n != 2 {
		t.Fatalf("%d connections", n)
	}
}

func TestRepeatedConnectReusesChannel(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	r := dialRaw(t, s)
	first := r.ch
	resp := r.connect(knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer))
	if resp.Status != knxnetip.StatusNoError || resp.Channel != first || resp.CRD.Address != slot1 {
		t.Fatalf("repeated connect: %+v (first channel %d)", resp, first)
	}
	if n := len(s.Connections()); n != 1 {
		t.Fatalf("%d connections", n)
	}
}

func TestConnectionStateAndDisconnect(t *testing.T) {
	leak.Check(t)
	s, m := start(t)
	r := dialRaw(t, s)
	r.p.Send(s.Addr(), &knxnetip.ConnectionStateRequest{Channel: r.ch + 1, Control: r.p.HPAI()})
	if resp, _ := fakeknx.Expect[*knxnetip.ConnectionStateResponse](r.p, wait); resp.Status != knxnetip.StatusConnectionID || resp.Channel != r.ch+1 {
		t.Fatalf("unknown channel: %+v", resp)
	}
	before := s.Connections()[0].LastSeen
	r.p.Send(s.Addr(), &knxnetip.ConnectionStateRequest{Channel: r.ch, Control: r.p.HPAI()})
	if resp, _ := fakeknx.Expect[*knxnetip.ConnectionStateResponse](r.p, wait); resp.Status != knxnetip.StatusNoError {
		t.Fatalf("known channel: %+v", resp)
	}
	c := s.Connections()[0]
	if c.Channel != r.ch || c.Address != slot1 || c.Control != r.p.Addr() || c.Data != r.p.Addr() || c.LastSeen.Before(before) {
		t.Fatalf("connection %+v", c)
	}
	// Disconnect of an unknown channel.
	r.p.Send(s.Addr(), &knxnetip.DisconnectRequest{Channel: r.ch + 1, Control: r.p.HPAI()})
	if resp, _ := fakeknx.Expect[*knxnetip.DisconnectResponse](r.p, wait); resp.Status != knxnetip.StatusConnectionID {
		t.Fatalf("unknown channel: %+v", resp)
	}
	// Our own DISCONNECT_RESPONSE is ignored.
	r.p.Send(s.Addr(), &knxnetip.DisconnectResponse{Channel: r.ch})
	r.p.Send(s.Addr(), &knxnetip.DisconnectRequest{Channel: r.ch, Control: r.p.HPAI()})
	if resp, _ := fakeknx.Expect[*knxnetip.DisconnectResponse](r.p, wait); resp.Status != knxnetip.StatusNoError {
		t.Fatalf("disconnect: %+v", resp)
	}
	if n := len(s.Connections()); n != 0 {
		t.Fatalf("%d connections after disconnect", n)
	}
	eventually(t, "disconnect metric", func() bool { return m.get(func(m *metrics) int { return len(m.disconnects) }) == 1 })
	// The slot is free again.
	dialRaw(t, s)
	dialRaw(t, s)
}

func TestHeartbeatTimeout(t *testing.T) {
	leak.Check(t)
	s, m := start(t, server.WithConnectionAliveTime(100*time.Millisecond))
	r := dialRaw(t, s)
	req, _ := fakeknx.Expect[*knxnetip.DisconnectRequest](r.p, wait)
	if req.Channel != r.ch {
		t.Fatalf("disconnect of channel %d", req.Channel)
	}
	if n := len(s.Connections()); n != 0 {
		t.Fatalf("%d connections", n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.disconnects) != 1 || !errors.Is(m.disconnects[0], knx.ErrConnectionLost) {
		t.Fatalf("disconnect metrics %v", m.disconnects)
	}
}

func TestHeartbeatKeepsConnection(t *testing.T) {
	leak.Check(t)
	s, _ := start(t, server.WithConnectionAliveTime(300*time.Millisecond))
	c := dialTunnel(t, s, tunnel.WithHeartbeat(30*time.Millisecond, time.Second, 3))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(s.Connections()) != 1 || c.State() != knx.StateConnected {
			t.Fatal("connection dropped despite heartbeats")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestClientNotAcking(t *testing.T) {
	leak.Check(t)
	s, m := start(t, server.WithRequestTimeout(50*time.Millisecond))
	r := dialRaw(t, s)
	if err := s.GroupWrite(ga, apdu.GroupValue{Data: []byte{1}, Small: true}); err != nil {
		t.Fatal(err)
	}
	a, _ := fakeknx.Expect[*knxnetip.TunnellingRequest](r.p, wait)
	b, _ := fakeknx.Expect[*knxnetip.TunnellingRequest](r.p, wait)
	if a.Seq != b.Seq || a.Seq != 0 {
		t.Fatalf("sequences %d %d", a.Seq, b.Seq)
	}
	// A wrong-sequence ack does not count.
	r.p.Send(s.Addr(), &knxnetip.TunnellingAck{Channel: r.ch, Seq: 7})
	req, _ := fakeknx.Expect[*knxnetip.DisconnectRequest](r.p, wait)
	if req.Channel != r.ch {
		t.Fatalf("disconnect %+v", req)
	}
	if len(s.Connections()) != 0 {
		t.Fatal("connection kept")
	}
	if n := m.get(func(m *metrics) int { return m.retransmits }); n != 1 {
		t.Fatalf("retransmits %d", n)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.disconnects) != 1 || !errors.Is(m.disconnects[0], knx.ErrConnectionLost) {
		t.Fatalf("disconnects %v", m.disconnects)
	}
}

func TestServerSequenceNumbers(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	r := dialRaw(t, s)
	for i := 0; i < 300; i++ {
		if err := s.GroupWrite(ga, apdu.GroupValue{Data: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
		req, d := fakeknx.Expect[*knxnetip.TunnellingRequest](r.p, wait)
		if req.Seq != uint8(i) {
			t.Fatalf("telegram %d has sequence %d", i, req.Seq)
		}
		r.p.Send(d.From, &knxnetip.TunnellingAck{Channel: r.ch, Seq: req.Seq})
	}
}

func TestConfirmationToOrigin(t *testing.T) {
	leak.Check(t)
	s, m := start(t)
	r := dialRaw(t, s)
	other := dialTunnel(t, s)
	expectAck := func(seq uint8) {
		t.Helper()
		a, _ := fakeknx.Expect[*knxnetip.TunnellingAck](r.p, wait)
		if a.Seq != seq || a.Channel != r.ch {
			t.Fatalf("ack %+v, want %d", a, seq)
		}
	}
	r.request(0, write(ga, 5))
	expectAck(0)
	con := r.nextFrame()
	if con.MsgCode != cemi.LDataCon || con.ConfirmError() || con.Source != slot1 || lastOctet(con) != 5 {
		t.Fatalf("confirmation %v", con)
	}
	ind := receive(t, other)
	if ind.MsgCode != cemi.LDataInd || ind.Source != slot1 || lastOctet(ind) != 5 {
		t.Fatalf("indication %v", ind)
	}
	// Repetition: acked, not delivered again.
	r.request(0, write(ga, 5))
	expectAck(0)
	// Out of order: not acked.
	r.request(9, write(ga, 6))
	// Not an L_Data.req: acked, ignored.
	ind = write(ga, 6)
	ind.MsgCode = cemi.LDataInd
	r.request(1, ind)
	expectAck(1)
	// A source address is kept.
	f := write(ga, 7)
	f.Source = knx.MustParseIndividualAddress("1.1.77")
	r.request(2, f)
	expectAck(2)
	con = r.nextFrame()
	if con.Source != f.Source || lastOctet(con) != 7 {
		t.Fatalf("confirmation %v", con)
	}
	if ind := receive(t, other); lastOctet(ind) != 7 || ind.Source != f.Source {
		t.Fatalf("indication %v", ind)
	}
	noFrame(t, other)
	// Undecodable cEMI is acked and counted.
	r.p.Send(r.data, &knxnetip.TunnellingRequest{Channel: r.ch, Seq: 3, CEMI: []byte{0x11, 0x00}})
	expectAck(3)
	// Requests on unknown channels and undecodable datagrams are counted.
	r.p.Send(r.data, &knxnetip.TunnellingRequest{Channel: r.ch + 50, Seq: 0, CEMI: []byte{0x11, 0x00}})
	r.p.SendRaw(s.Addr(), []byte{1, 2, 3})
	eventually(t, "metrics", func() bool {
		return m.get(func(m *metrics) int { return m.dropped["duplicate"] }) == 1 &&
			m.get(func(m *metrics) int { return m.dropped["sequence"] }) == 1 &&
			m.get(func(m *metrics) int { return m.dropped["unknown_channel"] }) == 1 &&
			m.get(func(m *metrics) int { return m.decode }) == 2
	})
}

func TestDeliveryAndDevices(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	dev := device.New("dev", knx.MustParseIndividualAddress("1.1.1"))
	temp, _ := device.NewGroupObject("temp", "9.001", "CRT", "1/2/4")
	sw, _ := device.NewGroupObject("switch", "1.001", "CRW", "1/2/3")
	dev.Add(temp, sw)
	_ = temp.Set(21.5)
	s.AddDevice(dev)
	a := dialTunnel(t, s)
	b := dialTunnel(t, s)

	tpdu, _ := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{1}, Small: true})
	if err := a.Send(ctx(t), cemi.NewGroupFrame(cemi.LDataReq, 0, ga, knx.PriorityLow, tpdu)); err != nil {
		t.Fatal(err)
	}
	if f := receive(t, b); f.Source != a.IndividualAddress() || f.MsgCode != cemi.LDataInd {
		t.Fatalf("b got %v", f)
	}
	noFrame(t, a) // the sender gets its confirmation only
	if v, ok, _ := sw.Value(); !ok || v != true {
		t.Fatalf("device switch %v %v", v, ok)
	}

	// A read is answered by the device; both clients see the response
	// (the reader also sees its read... no: only the others see the read).
	if err := a.Send(ctx(t), cemi.NewGroupFrame(cemi.LDataReq, 0, knx.MustParseGroupAddress("1/2/4"), knx.PriorityLow, apdu.GroupValueRead())); err != nil {
		t.Fatal(err)
	}
	resp := receive(t, a)
	if svc, v, err := apdu.ParseGroupValue(resp.TPDU); err != nil || svc != apdu.GroupValueResponseService || resp.Source != dev.Address {
		t.Fatalf("response %v %v %v", resp, svc, err)
	} else if got, _ := temp.Type.Decode(v.Data); got != 21.5 {
		t.Fatalf("value %v", got)
	}
	read := receive(t, b)
	if svc, _, _ := apdu.ParseGroupValue(read.TPDU); svc != apdu.GroupValueReadService {
		t.Fatalf("b first saw %v", read)
	}
	if r := receive(t, b); r.Source != dev.Address {
		t.Fatalf("b response %v", r)
	}
}

func TestServerSend(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	c := dialTunnel(t, s)
	var mu sync.Mutex
	var seen []server.Telegram
	cancel := s.Subscribe(func(tg server.Telegram) {
		mu.Lock()
		seen = append(seen, tg)
		mu.Unlock()
	})

	if err := s.GroupWrite(ga, apdu.GroupValue{Data: []byte{1}, Small: true}); err != nil {
		t.Fatal(err)
	}
	if f := receive(t, c); f.Source != serverAddr || f.MsgCode != cemi.LDataInd {
		t.Fatalf("GroupWrite: %v", f)
	}
	// Send: a zero source becomes the server's; the code L_Data.ind.
	f := write(ga, 9)
	if err := s.Send(f); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, c); got.Source != serverAddr || got.MsgCode != cemi.LDataInd || lastOctet(got) != 9 {
		t.Fatalf("Send: %v", got)
	}
	if f.MsgCode != cemi.LDataReq || f.Source != 0 {
		t.Fatal("Send modified its argument")
	}
	bad := write(ga, 1)
	bad.TPDU = nil
	if err := s.Send(bad); err == nil {
		t.Fatal("Send of an invalid frame")
	}
	if err := s.GroupWrite(ga, apdu.GroupValue{}); err == nil {
		t.Fatal("GroupWrite of an empty value")
	}

	// Transmit as a device.
	dev := device.New("dev", knx.MustParseIndividualAddress("1.1.1"))
	ct, _ := device.NewGroupObject("ct", "1.001", "CT", "1/2/5")
	quiet, _ := device.NewGroupObject("quiet", "1.001", "C", "1/2/6")
	dev.Add(ct, quiet)
	s.AddDevice(dev)
	if err := s.Transmit(dev, ct, true); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, c); got.Source != dev.Address {
		t.Fatalf("Transmit: %v", got)
	}
	if err := s.Transmit(dev, quiet, true); err != nil {
		t.Fatal(err)
	}
	noFrame(t, c)
	if err := s.Transmit(dev, ct, "x"); err == nil {
		t.Fatal("Transmit of a bad value")
	}

	cancel()
	if err := s.GroupWrite(ga, apdu.GroupValue{Data: []byte{0}, Small: true}); err != nil {
		t.Fatal(err)
	}
	receive(t, c)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[0].Origin != server.FromServer || seen[1].Origin != server.FromServer || seen[2].Origin != server.FromDevice {
		t.Fatalf("subscription saw %+v", seen)
	}
}

func TestSubscribeOrigins(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	got := make(chan server.Telegram, 8)
	defer s.Subscribe(func(tg server.Telegram) { got <- tg })()
	c := dialTunnel(t, s)
	if err := c.Send(ctx(t), write(ga, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case tg := <-got:
		if tg.Origin != server.FromTunnel || tg.Channel != c.Channel() || tg.Frame.Source != c.IndividualAddress() {
			t.Fatalf("telegram %+v", tg)
		}
	case <-time.After(wait):
		t.Fatal("no telegram")
	}
}

func TestQueueFull(t *testing.T) {
	leak.Check(t)
	s, m := start(t, server.WithQueueSize(1), server.WithRequestTimeout(time.Minute))
	r := dialRaw(t, s)
	gw := func(v byte) {
		t.Helper()
		if err := s.GroupWrite(ga, apdu.GroupValue{Data: []byte{v}}); err != nil {
			t.Fatal(err)
		}
	}
	gw(1)
	fakeknx.Expect[*knxnetip.TunnellingRequest](r.p, wait) // in flight, not acked
	gw(2)                                                  // queued
	gw(3)                                                  // dropped
	if n := m.get(func(m *metrics) int { return m.dropped["queue_full"] }); n != 1 {
		t.Fatalf("queue_full %d", n)
	}
	r.p.Send(s.Addr(), &knxnetip.TunnellingAck{Channel: r.ch, Seq: 0})
	if f := r.nextFrame(); lastOctet(f) != 2 {
		t.Fatalf("next frame %v", f)
	}
}

func TestConcurrentClients(t *testing.T) {
	leak.Check(t)
	const clients, writes = 8, 50
	s, _ := start(t, server.WithTunnelAddresses(addrs(clients)...), server.WithQueueSize(clients*writes))
	var mu sync.Mutex
	count := map[uint8]int{}
	defer s.Subscribe(func(tg server.Telegram) {
		mu.Lock()
		count[tg.Channel]++
		mu.Unlock()
	})()
	conns := make([]*tunnel.Conn, clients)
	for i := range conns {
		conns[i] = dialTunnel(t, s)
	}
	// Every client reads what the others send.
	var rwg sync.WaitGroup
	received := make([]int, clients)
	rctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i, c := range conns {
		rwg.Add(1)
		go func(i int, c *tunnel.Conn) {
			defer rwg.Done()
			for received[i] < (clients-1)*writes {
				if _, err := c.Receive(rctx); err != nil {
					return
				}
				received[i]++
			}
		}(i, c)
	}
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c *tunnel.Conn) {
			defer wg.Done()
			for j := 0; j < writes; j++ {
				if err := c.Send(context.Background(), write(ga, byte(j))); err != nil {
					t.Errorf("client %d write %d: %v", i, j, err)
					return
				}
			}
		}(i, c)
	}
	wg.Wait()
	done := make(chan struct{})
	go func() { rwg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cancel()
		<-done
		t.Fatalf("received %v, want %d each", received, (clients-1)*writes)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, c := range conns {
		if count[c.Channel()] != writes {
			t.Fatalf("channel %d: %d telegrams", c.Channel(), count[c.Channel()])
		}
	}
}

func TestCloseDisconnectsClients(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	c := dialTunnel(t, s)
	r := dialRaw(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if req, _ := fakeknx.Expect[*knxnetip.DisconnectRequest](r.p, wait); req.Channel != r.ch {
		t.Fatalf("disconnect %+v", req)
	}
	select {
	case <-c.Done():
	case <-time.After(wait):
		t.Fatal("client not disconnected")
	}
	if !errors.Is(c.Err(), knx.ErrConnectionLost) {
		t.Fatalf("client Err %v", c.Err())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(s.Connections()) != 0 {
		t.Fatal("connections after Close")
	}
	// A CONNECT_REQUEST after Close is not answered (the socket is gone).
}

func TestLifecycle(t *testing.T) {
	leak.Check(t)
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr().IsValid() {
		t.Fatal("address before Start")
	}
	if err := s.Close(); err != nil { // never started
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("Start after Close: %v", err)
	}

	s, err = server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(c) }()
	eventually(t, "serving", func() bool { return s.Addr().IsValid() })
	if err := s.Start(context.Background()); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("second Start: %v", err)
	}
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(wait):
		t.Fatal("Serve did not return")
	}

	// Serve returns when the server is closed from elsewhere.
	s, _ = server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false))
	go func() { served <- s.Serve(context.Background()) }()
	eventually(t, "serving", func() bool { return s.Addr().IsValid() })
	s.Close()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestOptionsAndStartErrors(t *testing.T) {
	leak.Check(t)
	for name, opt := range map[string]server.Option{
		"name":         server.WithName("a name that is much longer than thirty characters"),
		"no tunnels":   server.WithTunnelAddresses(),
		"duplicate":    server.WithTunnelAddresses(slot1, slot1),
		"ttl":          server.WithMulticastTTL(0),
		"alive":        server.WithConnectionAliveTime(0),
		"request":      server.WithRequestTimeout(0),
		"queue":        server.WithQueueSize(0),
		"routing rate": server.WithRoutingRate(-1),
	} {
		if _, err := server.New(opt); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Accepted options.
	if _, err := server.New(server.WithLogger(nil), server.WithMetrics(nil), server.WithLogger(knx.NopLogger()),
		server.WithMulticastTTL(4), server.WithRoutingRate(0)); err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string][]server.Option{
		"listen":         {server.WithListenAddr("127.0.0.1:x")},
		"group":          {server.WithListenAddr("127.0.0.1:0"), server.WithMulticastGroup("239.1.1.1:x")},
		"unicast group":  {server.WithListenAddr("127.0.0.1:0"), server.WithMulticastGroup("10.0.0.1:3671")},
		"interface":      {server.WithListenAddr("127.0.0.1:0"), server.WithInterface("no-such-interface0")},
		"routing port":   {server.WithListenAddr("127.0.0.1:0"), server.WithRouting(true), server.WithDiscovery(false)},
		"listen foreign": {server.WithListenAddr("192.0.2.1:0"), server.WithDiscovery(false)},
	} {
		s, err := server.New(opts...)
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		if err := s.Start(context.Background()); err == nil {
			s.Close()
			t.Errorf("%s: Start succeeded", name)
		}
		s.Close()
	}
}

func TestInterfaceAndDiscoverySocket(t *testing.T) {
	leak.Check(t)
	lo := loopbackName(t)
	// The discovery socket is best effort: Start succeeds either way.
	s, _ := start(t, server.WithInterface(lo), server.WithDiscovery(true), server.WithListenAddr(":0"))
	p := fakeknx.Listen(t)
	p.Send(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s.Addr().Port()), &knxnetip.SearchRequest{Discovery: p.HPAI()})
	resp, _ := fakeknx.Expect[*knxnetip.SearchResponse](p, wait)
	if !resp.Control.Addr.Addr().IsLoopback() || resp.Control.Addr.Port() != s.Addr().Port() {
		t.Fatalf("control endpoint %s", resp.Control)
	}
	// Listening on the wildcard address without interface, the server
	// announces the address it is reached on.
	s2, _ := start(t, server.WithListenAddr(":0"))
	p.Send(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), s2.Addr().Port()), &knxnetip.SearchRequest{Discovery: p.HPAI()})
	resp, _ = fakeknx.Expect[*knxnetip.SearchResponse](p, wait)
	if !resp.Control.Addr.Addr().IsLoopback() {
		t.Fatalf("control endpoint %s", resp.Control)
	}
}

func loopbackName(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

func TestTinyAliveTime(t *testing.T) {
	leak.Check(t)
	// An alive time under 10 ns once gave the janitor a zero tick.
	s, _ := start(t, server.WithConnectionAliveTime(time.Nanosecond))
	r := dialRaw(t, s)
	fakeknx.Expect[*knxnetip.DisconnectRequest](r.p, wait)
}
