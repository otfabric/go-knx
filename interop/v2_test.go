// SPDX-License-Identifier: MIT

//go:build interop

package interop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/devmgmt"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/tunnel"
)

// startPeerServer starts a server adapter with its TCP and UDP port 3671
// published on the loopback interface, and waits for its description.
func startPeerServer(t *testing.T, peer, net string) (name, udpAddr, tcpAddr string) {
	t.Helper()
	id := docker(t, "run", "-d", "--network", net, "-p", "127.0.0.1::3671/udp", "-p", "127.0.0.1::3671/tcp", image(peer), "server", "--name", serverName)
	name = strings.TrimSpace(docker(t, "inspect", "-f", "{{.Name}}", id))[1:]
	udpAddr = strings.Split(docker(t, "port", id, "3671/udp"), "\n")[0]
	tcpAddr = strings.Split(docker(t, "port", id, "3671/tcp"), "\n")[0]
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		if _, err := describeNAT(ctx, udpAddr); err == nil {
			return name, udpAddr, tcpAddr
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s did not answer", peer)
	return
}

// TestGoKNXClientTCP: go-knx's TCP tunnel (tunnelling v2, feature services)
// against Calimero's server.
func TestGoKNXClientTCP(t *testing.T) {
	requireDocker(t)
	peer := "calimero-server"
	_, _, tcpAddr := startPeerServer(t, peer, network(t))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := client.DialTunnel(ctx, tcpAddr, []tunnel.Option{tunnel.WithTCP()})
	record(t, peer, "tunnel connect over TCP", err, "")
	if err != nil {
		t.FailNow()
	}
	defer c.Close()
	tc := c.Link().(*tunnel.Conn)
	v, err := tc.FeatureGet(ctx, knxnetip.FeatureSupportedEMIType)
	if err == nil && !bytes.Equal(v, []byte{0x00, 0x04}) {
		err = fmt.Errorf("supported EMI type % X, want 00 04 (cEMI)", v)
	}
	record(t, peer, "TUNNELLING_FEATURE_GET supported EMI type", err, "")
	v, err = tc.FeatureGet(ctx, knxnetip.FeatureIndividualAddress)
	if err == nil && (len(v) != 2 || knx.IndividualAddress(uint16(v[0])<<8|uint16(v[1])) != tc.IndividualAddress()) {
		err = fmt.Errorf("individual address % X, tunnel %s", v, tc.IndividualAddress())
	}
	record(t, peer, "TUNNELLING_FEATURE_GET individual address", err, "")
	err = c.GroupWrite(ctx, knx.MustParseGroupAddress("1/0/2"), 23.5, client.WithDPT("9.001"))
	record(t, peer, "group write over TCP confirmed", err, "")
	r, err := c.GroupRead(ctx, knx.MustParseGroupAddress("1/0/2"), client.WithDPT("9.001"))
	if err == nil && r.Decoded != 23.5 {
		err = fmt.Errorf("read %v", r.Decoded)
	}
	record(t, peer, "group read over TCP (emulated subnet)", err, "")
}

// TestGoKNXDeviceManagement: go-knx's device management client against
// Calimero's server, over UDP (NAT) and TCP.
func TestGoKNXDeviceManagement(t *testing.T) {
	requireDocker(t)
	peer := "calimero-server"
	_, udpAddr, tcpAddr := startPeerServer(t, peer, network(t))
	for _, mode := range []struct {
		name string
		addr string
		opts []tunnel.Option
	}{{"UDP", udpAddr, []tunnel.Option{tunnel.WithNAT(true)}}, {"TCP", tcpAddr, []tunnel.Option{tunnel.WithTCP()}}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		d, err := devmgmt.Dial(ctx, mode.addr, mode.opts...)
		record(t, peer, "device management connect ("+mode.name+")", err, "")
		if err != nil {
			cancel()
			continue
		}
		b, err := d.PropRead(ctx, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDFriendlyName, 1, 12)
		if err == nil && !strings.HasPrefix(string(b), serverName) {
			err = fmt.Errorf("friendly name %q", b)
		}
		record(t, peer, "M_PropRead friendly name ("+mode.name+")", err, string(bytes.TrimRight(b, "\x00")))
		_, err = d.PropRead(ctx, devmgmt.ObjectDevice, 1, 250, 1, 1)
		var pe *devmgmt.PropertyError
		if errors.As(err, &pe) && pe.Code == 0x07 {
			err = nil
		} else if err == nil {
			err = fmt.Errorf("a read of property 250 succeeded")
		}
		record(t, peer, "negative M_PropRead.con for an unknown property ("+mode.name+")", err, "")
		d.Close()
		cancel()
	}
}

// TestGoKNXBusmonitor: go-knx's busmonitor tunnel against knxd's server,
// with a write of xknx through the same server.
func TestGoKNXBusmonitor(t *testing.T) {
	requireDocker(t)
	peer := "knxd"
	net := network(t)
	name, udpAddr, _ := startPeerServer(t, peer, net)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	mon, err := tunnel.Dial(ctx, udpAddr, tunnel.WithNAT(true), tunnel.WithLayer(knxnetip.TunnelBusmonitor))
	record(t, peer, "busmonitor connect", err, "")
	if err != nil {
		t.FailNow()
	}
	defer mon.Close()
	_, err = runClient(ctx, "xknx", []string{"--network", net}, "write", "--target", name, "--group", "1/0/9", "--dpt", "9.001", "--value", "21.5")
	if err != nil {
		record(t, peer, "busmonitor sees a write of xknx", err, "")
		return
	}
	rc, rcancel := context.WithTimeout(ctx, 10*time.Second)
	defer rcancel()
	for {
		f, err := mon.Receive(rc)
		if err != nil {
			record(t, peer, "busmonitor sees a write of xknx", err, "")
			return
		}
		raw, ok := f.(*cemi.Raw)
		if !ok || raw.MsgCode != cemi.LBusmonInd {
			continue
		}
		ld, err := cemi.ParseTP1(raw.Data)
		if err == nil {
			if g, _ := ld.Group(); g != knx.MustParseGroupAddress("1/0/9") || !bytes.Equal(ld.TPDU, []byte{0x00, 0x80, 0x0C, 0x33}) {
				continue
			}
		}
		record(t, peer, "busmonitor sees a write of xknx (TP1 frame, check octet)", err, fmt.Sprintf("% X", raw.Data))
		return
	}
}

func describeNAT(ctx context.Context, addr string) (knxnetip.DIBs, error) {
	return discovery.Describe(ctx, addr, discovery.WithNAT(true), discovery.WithTimeout(2*time.Second))
}
