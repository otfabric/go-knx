// SPDX-License-Identifier: MIT

package e2e

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/devmgmt"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// TestTCPTunnel: tunnelling over TCP with the feature services, against
// the server's TCP listener, together with a UDP client.
func TestTCPTunnel(t *testing.T) {
	s, addr := startServer(t, server.WithName("tcp"))
	dev := device.New("dev", knx.MustParseIndividualAddress("1.1.1"))
	temp, _ := device.NewGroupObject("t", "9.001", "CRWU", "1/2/4")
	_ = temp.Set(21.5)
	dev.Add(temp)
	s.AddDevice(dev)
	c := ctx(t)

	tcp, err := client.DialTunnel(c, addr, []tunnel.Option{tunnel.WithTCP()})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udpc, err := client.DialTunnel(c, addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer udpc.Close()
	tc := tcp.Link().(*tunnel.Conn)
	if !tc.TCP() {
		t.Fatal("not a TCP connection")
	}

	v, err := tc.FeatureGet(c, knxnetip.FeatureIndividualAddress)
	if err != nil || len(v) != 2 || knx.IndividualAddress(uint16(v[0])<<8|uint16(v[1])) != tc.IndividualAddress() {
		t.Fatalf("individual address feature % X %v (tunnel %s)", v, err, tc.IndividualAddress())
	}
	if v, err = tc.FeatureGet(c, knxnetip.FeatureSupportedEMIType); err != nil || !bytes.Equal(v, []byte{0, 4}) {
		t.Fatalf("EMI type % X %v", v, err)
	}
	if err := tc.FeatureSet(c, knxnetip.FeatureMaxAPDULength, []byte{0, 15}); !errors.Is(err, knx.ErrRejected) {
		t.Fatalf("set of a read-only feature: %v", err)
	}
	if err := tc.FeatureSet(c, knxnetip.FeatureInfoServiceEnable, []byte{1}); err != nil {
		t.Fatalf("info service enable: %v", err)
	}
	// Feature services over UDP (acknowledged).
	if _, err := udpc.Link().(*tunnel.Conn).FeatureGet(c, knxnetip.FeatureBusConnectionStatus); err != nil {
		t.Fatalf("UDP feature get: %v", err)
	}

	sub := udpc.Subscribe(4, knx.MustParseGroupAddress("1/2/4"))
	if err := tcp.GroupWrite(c, knx.MustParseGroupAddress("1/2/4"), -12.5, client.WithDPT("9.001")); err != nil {
		t.Fatal(err)
	}
	select {
	case tg := <-sub.C():
		if v, err := tg.Decode("9.001"); v != -12.5 {
			t.Fatalf("UDP client saw %v (%v): %+v %s", v, err, tg.Value, tg.Frame)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the UDP client saw nothing from the TCP client")
	}
	r, err := tcp.GroupRead(c, knx.MustParseGroupAddress("1/2/4"), client.WithDPT("9.001"))
	if err != nil || r.Decoded != -12.5 {
		t.Fatalf("read over TCP: %v %v", r.Decoded, err)
	}

	// Closing the TCP connection frees its tunnel.
	tcp.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(s.Connections()) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(s.Connections()); n != 1 {
		t.Fatalf("%d connections after the TCP client closed", n)
	}
}

func TestDeviceManagement(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		name := "udp"
		var opts []tunnel.Option
		if tcp {
			name, opts = "tcp", []tunnel.Option{tunnel.WithTCP()}
		}
		t.Run(name, func(t *testing.T) {
			_, addr := startServer(t, server.WithName("devmgmt server"))
			c := ctx(t)
			d, err := devmgmt.Dial(c, addr, opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			n, err := d.PropElements(c, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDFriendlyName)
			if err != nil || n != 30 {
				t.Fatalf("friendly name elements %d %v", n, err)
			}
			b, err := d.PropRead(c, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDFriendlyName, 1, 15)
			if err != nil || !strings.HasPrefix(string(b), "devmgmt server") {
				t.Fatalf("friendly name %q %v", b, err)
			}
			b, err = d.PropRead(c, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDAdditionalIndividualAddrs, 1, 2)
			if err != nil || !bytes.Equal(b, []byte{0x11, 0x0A, 0x11, 0x0B}) {
				t.Fatalf("tunnelling addresses % X %v", b, err)
			}
			b, err = d.PropRead(c, devmgmt.ObjectRouter, 1, devmgmt.PIDMediumStatus, 1, 1)
			if err != nil || !bytes.Equal(b, []byte{0}) {
				t.Fatalf("medium status % X %v", b, err)
			}
			_, err = d.PropRead(c, devmgmt.ObjectDevice, 1, 200, 1, 1)
			var pe *devmgmt.PropertyError
			if !errors.As(err, &pe) || pe.Code != 0x07 {
				t.Fatalf("unknown property: %v", err)
			}
			if err := d.PropWrite(c, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDFriendlyName, 1, 1, []byte{'x'}); !errors.Is(err, knx.ErrRejected) {
				t.Fatalf("write: %v", err)
			}
		})
	}
}

func TestBusmonitor(t *testing.T) {
	_, addr := startServer(t)
	c := ctx(t)
	mon, err := tunnel.Dial(c, addr, tunnel.WithLayer(knxnetip.TunnelBusmonitor))
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()
	w, err := client.DialTunnel(c, addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.GroupWrite(c, knx.MustParseGroupAddress("3/4/5"), true); err != nil {
		t.Fatal(err)
	}
	rc, cancel := context.WithTimeout(c, 3*time.Second)
	defer cancel()
	f, err := mon.Receive(rc)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := f.(*cemi.Raw)
	if !ok || raw.MsgCode != cemi.LBusmonInd {
		t.Fatalf("frame %T %v", f, f)
	}
	ld, err := cemi.ParseTP1(raw.Data)
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := ld.Group(); g != knx.MustParseGroupAddress("3/4/5") || !bytes.Equal(ld.TPDU, []byte{0x00, 0x81}) {
		t.Fatalf("monitored %s", ld)
	}
}
