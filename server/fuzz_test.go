// SPDX-License-Identifier: MIT

package server_test

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
)

// localOnly reports whether every HPAI of a datagram that decodes points
// at the loopback interface or asks for route back: the fuzzer must not
// make the server send to arbitrary hosts.
func localOnly(b []byte) bool {
	m, err := knxnetip.Parse(b)
	if err != nil {
		return true
	}
	v := reflect.ValueOf(m)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return true
	}
	v = v.Elem()
	hpaiType := reflect.TypeFor[knxnetip.HPAI]()
	for _, field := range v.Fields() {
		if field.Type() != hpaiType {
			continue
		}
		h := field.Interface().(knxnetip.HPAI)
		if a := h.Addr.Addr(); a.IsValid() && !a.IsLoopback() && !a.IsUnspecified() {
			return false
		}
	}
	return true
}

func fuzzServers(t testing.TB) []*server.Server {
	t.Helper()
	dev := device.New("dev", knx.MustParseIndividualAddress("1.1.1"))
	sw, _ := device.NewGroupObject("switch", "1.001", "CRWTU", "1/2/3")
	dev.Add(sw)
	plain, _ := start(t, server.WithConnectionAliveTime(300*time.Millisecond), server.WithRequestTimeout(20*time.Millisecond))
	plain.AddDevice(dev)
	devKey, _ := secure.DeviceAuthenticationCode("trustme")
	u2, _ := secure.UserPasswordKey("secret2")
	sec, _ := start(t, server.WithConnectionAliveTime(300*time.Millisecond), server.WithRequestTimeout(20*time.Millisecond),
		server.WithSecure(devKey, map[uint8]server.SecureUser{2: {Key: u2}}))
	return []*server.Server{plain, sec}
}

func fuzzDatagramSeeds(f *testing.F) {
	f.Helper()
	lo := knxnetip.NewHPAI(netip.MustParseAddrPort("127.0.0.1:9"))
	ld := cemi.NewGroupFrame(cemi.LDataReq, 0, knx.MustParseGroupAddress("1/2/3"), knx.PriorityLow, []byte{0x00, 0x81})
	ldb, _ := cemi.Marshal(ld)
	for _, m := range []knxnetip.Message{
		&knxnetip.SearchRequest{Discovery: knxnetip.RouteBackHPAI()},
		&knxnetip.DescriptionRequest{Control: knxnetip.RouteBackHPAI()},
		&knxnetip.ConnectRequest{Control: knxnetip.RouteBackHPAI(), Data: knxnetip.RouteBackHPAI(), CRI: knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)},
		&knxnetip.ConnectRequest{Control: lo, Data: lo, CRI: knxnetip.CRI{Type: knxnetip.DeviceManagementConnection}},
		&knxnetip.ConnectionStateRequest{Channel: 1, Control: knxnetip.RouteBackHPAI()},
		&knxnetip.DisconnectRequest{Channel: 1, Control: knxnetip.RouteBackHPAI()},
		&knxnetip.TunnellingRequest{Channel: 1, Seq: 0, CEMI: ldb},
		&knxnetip.TunnellingAck{Channel: 1, Seq: 0},
		&knxnetip.SessionRequest{Control: knxnetip.RouteBackHPAI(), PublicKey: [32]byte{9}},
		&knxnetip.RoutingIndication{CEMI: ldb},
	} {
		b, err := knxnetip.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0x06, 0x10, 0x02, 0x05, 0xff, 0xff})
	f.Add([]byte{0x06, 0x10, 0x04, 0x20, 0x00, 0x06})
	f.Add([]byte{})
}

// probeUDP checks that s answers a DESCRIPTION_REQUEST over UDP, with
// retries: under -race on a loaded machine a datagram may be lost.
func probeUDP(t testing.TB, probe *net.UDPConn, s *server.Server) {
	t.Helper()
	req, _ := knxnetip.Marshal(&knxnetip.DescriptionRequest{Control: knxnetip.NewHPAI(probe.LocalAddr().(*net.UDPAddr).AddrPort())})
	buf := make([]byte, 2048)
	for range 10 {
		if _, err := probe.WriteToUDPAddrPort(req, addrOf(s)); err != nil {
			t.Fatal(err)
		}
		_ = probe.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		for {
			n, _, err := probe.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			if m, err := knxnetip.Parse(buf[:n]); err == nil {
				if _, ok := m.(*knxnetip.DescriptionResponse); ok {
					return
				}
			}
		}
	}
	t.Fatal("the server no longer answers DESCRIPTION_REQUEST")
}

// FuzzServerDatagram sends arbitrary datagrams to a plain and a secure
// server and checks after each that both still answer a description
// request and hold no more connections than they allow. The package's
// TestMain checks for goroutines left behind.
func FuzzServerDatagram(f *testing.F) {
	fuzzDatagramSeeds(f)
	srvs := fuzzServers(f)
	lo := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	src, err := net.ListenUDP("udp4", lo)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = src.Close() })
	probe, err := net.ListenUDP("udp4", lo)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = probe.Close() })
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 2048 || !localOnly(b) {
			return
		}
		for _, s := range srvs {
			if _, err := src.WriteToUDPAddrPort(b, addrOf(s)); err != nil {
				t.Fatal(err)
			}
		}
		for _, s := range srvs {
			probeUDP(t, probe, s)
			if n := len(s.Connections()); n > 2+4 {
				t.Fatalf("%d connections", n)
			}
		}
	})
}

// FuzzServerTCPStream writes arbitrary octets on a TCP connection to a
// plain and a secure server: lying length fields, partial frames, frames
// of 0 octets, claims up to 65535. After the client half-closes, the
// server must close the connection (it must not wait for octets that will
// not come), still accept and answer another TCP client, and end the
// tunnelling connections the stream opened.
func FuzzServerTCPStream(f *testing.F) {
	fuzzDatagramSeeds(f)
	for _, m := range []knxnetip.Message{
		&knxnetip.ConnectRequest{Control: knxnetip.TCPHPAI(), Data: knxnetip.TCPHPAI(), CRI: knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)},
		&knxnetip.SearchRequestExt{Discovery: knxnetip.TCPHPAI()},
		&knxnetip.DescriptionRequest{Control: knxnetip.TCPHPAI()},
		&knxnetip.SessionRequest{Control: knxnetip.TCPHPAI(), PublicKey: [32]byte{9}},
	} {
		b, _ := knxnetip.Marshal(m)
		f.Add(b)
		f.Add(append(append([]byte(nil), b...), b[:len(b)/2]...)) // a frame and a partial one
	}
	f.Add([]byte{0x06, 0x10, 0x02, 0x03, 0xff, 0xff}) // claims 65535 octets
	f.Add([]byte{0x06, 0x10, 0x02, 0x03, 0x00, 0x00}) // claims 0 octets
	f.Add([]byte{0x06, 0x10, 0x02, 0x03, 0x00, 0x06}) // header only
	srvs := fuzzServers(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			return
		}
		for _, s := range srvs {
			streamOnce(t, s, b)
			probeTCP(t, s)
		}
		for _, s := range srvs {
			deadline := time.Now().Add(2 * time.Second)
			for len(s.Connections()) != 0 {
				if time.Now().After(deadline) {
					t.Fatalf("connections of closed TCP clients remain: %+v", s.Connections())
				}
				time.Sleep(time.Millisecond)
			}
		}
	})
}

func streamOnce(t *testing.T, s *server.Server, b []byte) {
	t.Helper()
	c, err := net.DialTCP("tcp4", nil, net.TCPAddrFromAddrPort(addrOf(s)))
	if err != nil {
		t.Fatal(err)
	}
	// A reset instead of TIME_WAIT: the fuzzer opens thousands of
	// connections a second and would exhaust the ephemeral ports.
	_ = c.SetLinger(0)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write(b) // the server may close early on garbage
	_ = c.CloseWrite()
	if _, err := io.Copy(io.Discard, c); err != nil && !isReset(err) {
		t.Fatalf("the server did not close a half-closed connection: %v", err)
	}
}

func isReset(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true // a reset after the server closed with unread data
}

// probeTCP checks that s accepts a TCP client and answers its
// DESCRIPTION_REQUEST.
func probeTCP(t testing.TB, s *server.Server) {
	t.Helper()
	var lastErr error
	for range 20 {
		if lastErr = describeTCP(s); lastErr == nil {
			return
		}
		time.Sleep(5 * time.Millisecond) // the server releases a slot when its reader ends
	}
	t.Fatalf("the server does not answer over TCP: %v", lastErr)
}

func describeTCP(s *server.Server) error {
	c, err := net.DialTCP("tcp4", nil, net.TCPAddrFromAddrPort(addrOf(s)))
	if err != nil {
		return err
	}
	_ = c.SetLinger(0)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	req, _ := knxnetip.Marshal(&knxnetip.DescriptionRequest{Control: knxnetip.TCPHPAI()})
	if _, err := c.Write(req); err != nil {
		return err
	}
	fr, err := knxnetip.ReadFrame(c)
	if err != nil {
		return err
	}
	m, err := knxnetip.Parse(fr)
	if err != nil {
		return err
	}
	if _, ok := m.(*knxnetip.DescriptionResponse); !ok {
		return errors.New("answer " + m.Service().String())
	}
	return nil
}
