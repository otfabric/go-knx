// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/capture"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/server"
)

// recordedRouter is the ABB IP-Router IPR/S of the wireshark-14825
// recordings (at 192.168.0.10, later 192.168.0.11).
var recordedRouter = map[netip.Addr]bool{
	netip.MustParseAddr("192.168.0.10"): true,
	netip.MustParseAddr("192.168.0.11"): true,
}

// controlRequest is a connection management request the test client
// sent the router over UDP, with the router's recorded answer.
type controlRequest struct {
	frame int
	time  time.Time
	from  netip.AddrPort // the client's recorded source
	reset bool           // an M_Reset.req: the router restarted
	req   knxnetip.Message
	resp  knxnetip.Message
}

// controlRequests pairs every CONNECT_REQUEST, CONNECTIONSTATE_REQUEST
// and DISCONNECT_REQUEST the client sent the router over UDP with the
// router's answer: the next datagram from the router's port to the
// client's port with the answering service. Requests without an answer
// are skipped.
func controlRequests(t *testing.T, f *capture.File) []controlRequest {
	t.Helper()
	answer := map[knxnetip.ServiceType]knxnetip.ServiceType{
		knxnetip.ConnectRequestType:         knxnetip.ConnectResponseType,
		knxnetip.ConnectionStateRequestType: knxnetip.ConnectionStateResponseType,
		knxnetip.DisconnectRequestType:      knxnetip.DisconnectResponseType,
	}
	var out []controlRequest
	for i, d := range f.IP {
		if d.Transport != capture.UDP || !recordedRouter[d.Dst.Addr()] || d.Dst.Port() != capture.Port {
			continue
		}
		req, err := knxnetip.Parse(d.Data)
		if err != nil {
			continue
		}
		if dc, ok := req.(*knxnetip.DeviceConfigurationRequest); ok && len(dc.CEMI) > 0 && dc.CEMI[0] == 0xF1 {
			out = append(out, controlRequest{frame: d.Frame, time: d.Time, from: d.Src, reset: true})
			continue
		}
		want, ok := answer[req.Service()]
		if !ok {
			continue
		}
		for _, r := range f.IP[i+1 : min(i+40, len(f.IP))] {
			if r.Transport != capture.UDP || r.Src != d.Dst || r.Dst != d.Src {
				continue
			}
			if m, err := knxnetip.Parse(r.Data); err == nil && m.Service() == want {
				out = append(out, controlRequest{frame: d.Frame, time: d.Time, from: d.Src, req: req, resp: m})
				break
			}
		}
	}
	return out
}

// activity returns, per channel, the times the client sent the router a
// frame of that connection (requests and acknowledgements with a
// connection header, heartbeats).
func activity(f *capture.File) map[uint8][]time.Time {
	out := map[uint8][]time.Time{}
	for _, d := range f.IP {
		if !recordedRouter[d.Dst.Addr()] {
			continue
		}
		m, err := knxnetip.Parse(d.Data)
		if err != nil {
			continue
		}
		var ch uint8
		switch m := m.(type) {
		case *knxnetip.TunnellingRequest:
			ch = m.Channel
		case *knxnetip.TunnellingAck:
			ch = m.Channel
		case *knxnetip.DeviceConfigurationRequest:
			ch = m.Channel
		case *knxnetip.DeviceConfigurationAck:
			ch = m.Channel
		case *knxnetip.ConnectionStateRequest:
			ch = m.Channel
		default:
			continue
		}
		out[ch] = append(out[ch], d.Time)
	}
	return out
}

// aliveTime is the KNXnet/IP connection alive time: a server ends a
// connection without a frame from its client for 120 s.
const aliveTime = 120 * time.Second

// TestCaptureConnectionManagement replays the connection management the
// test client ran against the ABB IP-Router IPR/S (wireshark-14825) on a
// go-knx server with the router's five tunnelling addresses (2.1.1 to
// 2.1.5), request by request in recorded order, and compares the answers
// by service and status: 1008 of the 1063 requests are answered alike.
//
// Comparison rules: each recorded client endpoint is a socket of its own
// and the HPAIs of a request name it (the recorded ones name the client's
// host); a channel the router assigned is replaced by the one the server
// assigned in its place, a channel the router never assigned (or go-knx
// refused) by 0xEE. Where the recording shows the router's state change
// without a request the replay can send, the replay brings the server
// into the same state: it ends go-knx's connections on the client's
// M_Reset.req (the router restarts, go-knx's virtual server does not),
// when the client has not used a connection for the 120 s alive time
// (the router ends it, the replay does not wait), and when the router
// assigns a channel number that is still open in the replay; a connection
// the router refused and go-knx accepted is ended again at once.
//
// The 47 remaining differences (pinned; 8 more requests follow from
// them) are classified as the router's configuration or state differing
// from go-knx's. Established for E_NO_MORE_UNIQUE_CONNECTIONS: the client
// had written the same address (1.1.111) into all five tunnelling slots
// (M_PropWrite PID 53). The others fall in stretches where the client
// sets the router up for KNX IP Secure (E_CONNECTION_TYPE for plain
// connections), holds connections the replay does not see (over TCP or
// in a secure session: E_NO_MORE_CONNECTIONS) or tests without the bus
// (E_KNX_CONNECTION): evidence incomplete, none shown to be a go-knx
// defect.
func TestCaptureConnectionManagement(t *testing.T) {
	files := []string{
		"wireshark-14825/test-tool_abb-ipr-s_00-setup.txt",
		"wireshark-14825/test-tool_abb-ipr-s_01-core.txt",
		"wireshark-14825/test-tool_abb-ipr-s_02-devicemanagement.txt",
		"wireshark-14825/test-tool_abb-ipr-s_03-tunneling.txt",
		"wireshark-14825/test-tool_abb-ipr-s_04-routing.txt",
		"wireshark-14825/test-tool_abb-ipr-s_05-remotediagandconfig.txt",
		"wireshark-14825/test-tool_abb-ipr-s_06-medium.txt",
		"wireshark-14825/test-tool_abb-ipr-s_07-security.txt",
		"wireshark-14825/test-tool_abb-ipr-s_08-systembroadcast.txt",
	}
	got := map[string]int{}
	for _, rel := range files {
		f, err := capture.Load(rel)
		if err != nil {
			t.Fatal(err)
		}
		reqs := controlRequests(t, f)
		res := replayControl(t, reqs, activity(f))
		for k, v := range res {
			got[k] += v
		}
		t.Logf("%s: %d requests %v", rel, len(reqs), res)
	}
	t.Logf("total %v", got)
	want := map[string]int{
		"equal CONNECT_RESPONSE E_NO_ERROR":              508,
		"equal CONNECT_RESPONSE E_TUNNELLING_LAYER":      8,
		"equal CONNECT_RESPONSE E_NO_MORE_CONNECTIONS":   3,
		"equal CONNECT_RESPONSE E_CONNECTION_IN_USE":     1,
		"equal CONNECT_RESPONSE E_CONNECTION_TYPE":       1,
		"equal CONNECT_RESPONSE E_NO_TUNNELLING_ADDRESS": 1,
		"equal CONNECTIONSTATE_RESPONSE E_NO_ERROR":      10,
		"equal CONNECTIONSTATE_RESPONSE E_CONNECTION_ID": 1,
		"equal DISCONNECT_RESPONSE E_NO_ERROR":           474,
		"equal DISCONNECT_RESPONSE E_CONNECTION_ID":      1,
		// State the replay stands in for.
		"router restart": 9,
		"expired":        5,
		"channel reused": 14,
		// Differences in the router's configuration or unseen state.
		"router CONNECT_RESPONSE E_CONNECTION_TYPE, go-knx CONNECT_RESPONSE E_NO_ERROR":                15,
		"router CONNECT_RESPONSE E_NO_MORE_CONNECTIONS, go-knx CONNECT_RESPONSE E_NO_ERROR":            11,
		"router CONNECT_RESPONSE E_NO_ERROR, go-knx CONNECT_RESPONSE E_NO_MORE_CONNECTIONS":            8,
		"router CONNECT_RESPONSE E_NO_MORE_UNIQUE_CONNECTIONS, go-knx CONNECT_RESPONSE E_NO_ERROR":     4,
		"router DISCONNECT_RESPONSE E_NO_ERROR, go-knx DISCONNECT_RESPONSE E_CONNECTION_ID":            4,
		"router DISCONNECT_RESPONSE E_CONNECTION_ID, go-knx DISCONNECT_RESPONSE E_NO_ERROR":            2,
		"router CONNECTIONSTATE_RESPONSE E_NO_ERROR, go-knx CONNECTIONSTATE_RESPONSE E_CONNECTION_ID":  2,
		"router CONNECTIONSTATE_RESPONSE E_KNX_CONNECTION, go-knx CONNECTIONSTATE_RESPONSE E_NO_ERROR": 1,
		"follows a difference": 8,
	}
	if !maps.Equal(got, want) {
		t.Errorf("results %v, want %v", got, want)
	}
}

func replayControl(t *testing.T, reqs []controlRequest, act map[uint8][]time.Time) map[string]int {
	t.Helper()
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false),
		server.WithIndividualAddress(knx.MustParseIndividualAddress("2.1.0")),
		server.WithTunnelAddresses(knx.MustParseIndividualAddress("2.1.1"), knx.MustParseIndividualAddress("2.1.2"),
			knx.MustParseIndividualAddress("2.1.3"), knx.MustParseIndividualAddress("2.1.4"), knx.MustParseIndividualAddress("2.1.5")))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// One socket per recorded client endpoint: the server tells
	// connections apart by their endpoints.
	sockets := map[netip.AddrPort]*net.UDPConn{}
	defer func() {
		for _, c := range sockets {
			_ = c.Close()
		}
	}()
	socket := func(from netip.AddrPort) *net.UDPConn {
		if c := sockets[from]; c != nil {
			return c
		}
		c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
		if err != nil {
			t.Fatal(err)
		}
		sockets[from] = c
		return c
	}
	channels := map[uint8]uint8{} // recorded -> live
	owner := map[uint8]netip.AddrPort{}
	opened := map[uint8]time.Time{}
	mapCh := func(ch uint8) uint8 {
		if v, ok := channels[ch]; ok {
			return v
		}
		return 0xEE
	}
	// last returns when the client last used a recorded channel before t.
	last := func(ch uint8, t time.Time) time.Time {
		l := opened[ch]
		for _, a := range act[ch] {
			if a.After(l) && a.Before(t) {
				l = a
			}
		}
		return l
	}
	routerOnly := map[uint8]bool{} // channels the router assigned and go-knx refused
	res := map[string]int{}
	// end ends go-knx's connection live, which stands for the router's
	// recorded channel ch.
	end := func(ch, live uint8) {
		c := socket(owner[ch])
		me := knxnetip.NewHPAI(c.LocalAddr().(*net.UDPAddr).AddrPort())
		b, _ := knxnetip.Marshal(&knxnetip.DisconnectRequest{Channel: live, Control: me})
		if _, err := c.WriteToUDPAddrPort(b, s.Addr()); err != nil {
			t.Fatal(err)
		}
		readAnswer(t, c, knxnetip.DisconnectResponseType)
		delete(channels, ch)
	}
	endAll := func() {
		for ch, live := range channels {
			end(ch, live)
		}
		clear(routerOnly)
	}
	for _, r := range reqs {
		if r.reset {
			// The router restarts on M_Reset.req (its connections end and
			// its channel numbers start again at 1); go-knx's virtual
			// server has nothing to restart. The replay ends go-knx's
			// connections in its place.
			endAll()
			res["router restart"]++
			continue
		}
		// The router ended connections idle for the alive time; the
		// replay, which does not wait, ends them with a disconnect.
		for ch, live := range channels {
			if r.time.Sub(last(ch, r.time)) <= aliveTime {
				continue
			}
			end(ch, live)
			res["expired"]++
		}
		// A channel the router assigns again was ended by the router in a
		// way the recording does not show (a restart, a timeout of a
		// connection kept alive over another path): the replay ends
		// go-knx's connection of that channel too.
		if cr, ok := r.resp.(*knxnetip.ConnectResponse); ok && cr.Status == knxnetip.StatusNoError {
			if live, ok := channels[cr.Channel]; ok {
				end(cr.Channel, live)
				res["channel reused"]++
			}
			delete(routerOnly, cr.Channel)
		}
		c := socket(r.from)
		me := knxnetip.NewHPAI(c.LocalAddr().(*net.UDPAddr).AddrPort())
		switch m := r.req.(type) {
		case *knxnetip.ConnectionStateRequest:
			if routerOnly[m.Channel] {
				res["follows a difference"]++
				continue
			}
		case *knxnetip.DisconnectRequest:
			if routerOnly[m.Channel] {
				delete(routerOnly, m.Channel)
				res["follows a difference"]++
				continue
			}
		}
		var req knxnetip.Message
		switch m := r.req.(type) {
		case *knxnetip.ConnectRequest:
			req = &knxnetip.ConnectRequest{Control: me, Data: me, CRI: m.CRI}
		case *knxnetip.ConnectionStateRequest:
			req = &knxnetip.ConnectionStateRequest{Channel: mapCh(m.Channel), Control: me}
		case *knxnetip.DisconnectRequest:
			req = &knxnetip.DisconnectRequest{Channel: mapCh(m.Channel), Control: me}
		}
		b, err := knxnetip.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.WriteToUDPAddrPort(b, s.Addr()); err != nil {
			t.Fatal(err)
		}
		live := readAnswer(t, c, r.resp.Service())
		k := compareControl(r, live, channels)
		cr, _ := r.resp.(*knxnetip.ConnectResponse)
		lr, _ := live.(*knxnetip.ConnectResponse)
		switch {
		case cr != nil && cr.Status == knxnetip.StatusNoError && lr != nil && lr.Status == knxnetip.StatusNoError:
			owner[cr.Channel], opened[cr.Channel] = r.from, r.time
		case cr != nil && cr.Status == knxnetip.StatusNoError:
			routerOnly[cr.Channel] = true
		case lr != nil && lr.Status == knxnetip.StatusNoError:
			// The router refused: the replay ends go-knx's connection
			// again, so that the states stay comparable.
			b, _ := knxnetip.Marshal(&knxnetip.DisconnectRequest{Channel: lr.Channel, Control: me})
			if _, err := c.WriteToUDPAddrPort(b, s.Addr()); err != nil {
				t.Fatal(err)
			}
			readAnswer(t, c, knxnetip.DisconnectResponseType)
		}
		if dr, ok := r.req.(*knxnetip.DisconnectRequest); ok {
			delete(channels, dr.Channel)
		}
		if k[:5] != "equal" {
			cri := ""
			if m, ok := r.req.(*knxnetip.ConnectRequest); ok {
				cri = fmt.Sprintf("%+v", m.CRI)
			}
			t.Logf("frame %d %s %s from %s: %s", r.frame, r.req.Service(), cri, r.from, k)
		}
		res[k]++
	}
	return res
}

func readAnswer(t *testing.T, c *net.UDPConn, want knxnetip.ServiceType) knxnetip.Message {
	t.Helper()
	buf := make([]byte, 2048)
	deadline := time.Now().Add(time.Second)
	for {
		_ = c.SetReadDeadline(deadline)
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return nil
		}
		if m, err := knxnetip.Parse(buf[:n]); err == nil && m.Service() == want {
			return m
		}
	}
}

func status(m knxnetip.Message) string {
	switch m := m.(type) {
	case *knxnetip.ConnectResponse:
		return fmt.Sprintf("%s %s", m.Service(), m.Status)
	case *knxnetip.ConnectionStateResponse:
		return fmt.Sprintf("%s %s", m.Service(), m.Status)
	case *knxnetip.DisconnectResponse:
		return fmt.Sprintf("%s %s", m.Service(), m.Status)
	case nil:
		return "no answer"
	}
	return m.Service().String()
}

// compareControl classifies the server's answer against the router's and
// records an assigned channel.
func compareControl(r controlRequest, live knxnetip.Message, channels map[uint8]uint8) string {
	rec, got := status(r.resp), status(live)
	if cr, ok := r.resp.(*knxnetip.ConnectResponse); ok && cr.Status == knxnetip.StatusNoError {
		if lr, ok := live.(*knxnetip.ConnectResponse); ok && lr.Status == knxnetip.StatusNoError {
			channels[cr.Channel] = lr.Channel
		}
	}
	if rec == got {
		return "equal " + rec
	}
	return "router " + rec + ", go-knx " + got
}
