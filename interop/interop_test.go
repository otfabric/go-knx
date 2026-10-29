// SPDX-License-Identifier: MIT

//go:build interop

package interop

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

const serverName = "knx-interop"

func network(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("goknx-interop-%d", time.Now().UnixNano())
	docker(t, "network", "create", name)
	t.Cleanup(func() {
		ids := strings.Fields(docker(t, "ps", "-aq", "--filter", "network="+name))
		if len(ids) > 0 {
			_ = runQuiet(append([]string{"rm", "-f"}, ids...)...)
		}
		_ = runQuiet("network", "rm", name)
	})
	return name
}

func runQuiet(args ...string) error { return execDocker(args...) }

// TestGoKNXClient runs go-knx's tunnelling client against independent
// KNXnet/IP servers.
func TestGoKNXClient(t *testing.T) {
	requireDocker(t)
	for _, peer := range []string{"calimero-server", "knxd"} {
		t.Run(peer, func(t *testing.T) {
			net := network(t)
			id := docker(t, "run", "-d", "--network", net, "-p", "127.0.0.1::3671/udp", image(peer), "server", "--name", serverName)
			name := strings.TrimSpace(docker(t, "inspect", "-f", "{{.Name}}", id))[1:]
			addr := docker(t, "port", id, "3671/udp")
			addr = strings.Split(addr, "\n")[0]
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()

			// Description, once the server answers.
			var err error
			deadline := time.Now().Add(90 * time.Second)
			for time.Now().Before(deadline) {
				d, derr := discovery.Describe(ctx, addr, discovery.WithNAT(true), discovery.WithTimeout(2*time.Second))
				if err = derr; err == nil {
					info, _ := d.DeviceInfo()
					if !strings.Contains(info.Name, serverName) {
						err = fmt.Errorf("device name %q", info.Name)
					}
					record(t, peer, "describe (NAT)", err, info.Name)
					break
				}
				time.Sleep(time.Second)
			}
			if err != nil {
				record(t, peer, "describe (NAT)", err, "")
				t.FailNow()
			}

			c, err := client.DialTunnel(ctx, addr, []tunnel.Option{tunnel.WithNAT(true)})
			record(t, peer, "tunnel connect (NAT)", err, "")
			if err != nil {
				t.FailNow()
			}
			defer c.Close()
			tc := c.Link().(*tunnel.Conn)
			t.Logf("channel %d, address %s", tc.Channel(), tc.IndividualAddress())

			// Write, confirmed by L_Data.con, and seen by an independent client.
			obs := background(t, "xknx", []string{"--network", net}, "monitor", "--target", name, "--count", "1", "--timeout", "20")
			err = c.GroupWrite(ctx, knx.MustParseGroupAddress("1/0/1"), true)
			record(t, peer, "group write confirmed (L_Data.con)", err, "")
			d, oerr := obs()
			if oerr == nil {
				oerr = expectTelegram(d, "1/0/1", "write", "01")
			}
			record(t, peer, "group write seen by xknx", oerr, "")

			// Inbound: a write of xknx through the server reaches go-knx.
			sub := c.Subscribe(16, knx.MustParseGroupAddress("1/0/3"))
			_, err = runClient(ctx, "xknx", []string{"--network", net}, "write", "--target", name, "--group", "1/0/3", "--dpt", "9.001", "--value", "-30")
			if err == nil {
				select {
				case tg := <-sub.C():
					v, derr := tg.Decode("9.001")
					if derr == nil && v != -30.0 {
						derr = fmt.Errorf("value %v", v)
					}
					err = derr
				case <-time.After(10 * time.Second):
					err = fmt.Errorf("no telegram")
				}
			}
			record(t, peer, "group write from xknx received", err, "")

			// Read: answered by an independent responder (and, on Calimero's
			// emulated subnet, by the subnet).
			ans := background(t, "xknx", []string{"--network", net}, "answer", "--target", name, "--group", "1/0/2", "--dpt", "9.001", "--value", "21.5", "--count", "1", "--timeout", "20")
			rctx, rcancel := context.WithTimeout(ctx, 8*time.Second)
			r, err := c.GroupRead(rctx, knx.MustParseGroupAddress("1/0/2"), client.WithDPT("9.001"))
			rcancel()
			if err == nil && r.Decoded != 21.5 {
				err = fmt.Errorf("response %v from %s", r.Decoded, r.Source)
			}
			record(t, peer, "group read answered by xknx", err, "")
			_, _ = ans()
		})
	}
}

func expectTelegram(d adapterDoc, group, service, data string) error {
	tels, _ := d.Data["telegrams"].([]any)
	for _, x := range tels {
		m, _ := x.(map[string]any)
		if m["group"] == group && m["service"] == service {
			if !strings.EqualFold(fmt.Sprint(m["data"]), data) {
				return fmt.Errorf("observer saw data %v, want %s", m["data"], data)
			}
			return nil
		}
	}
	return fmt.Errorf("observer saw %v", d.Data)
}

func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestGoKNXServer runs independent tunnelling clients against go-knx's
// server.
func TestGoKNXServer(t *testing.T) {
	requireDocker(t)
	port := freePort(t)
	var tunnels []knx.IndividualAddress
	for i := 10; i < 18; i++ {
		tunnels = append(tunnels, knx.MustParseIndividualAddress(fmt.Sprintf("1.1.%d", i)))
	}
	s, err := server.New(server.WithListenAddr(fmt.Sprintf("0.0.0.0:%d", port)), server.WithDiscovery(false), server.WithName(serverName),
		server.WithIndividualAddress(knx.MustParseIndividualAddress("1.1.0")), server.WithTunnelAddresses(tunnels...),
		server.WithConcurrentBusmonitor(true))
	if err != nil {
		t.Fatal(err)
	}
	dev := device.New("dev", knx.MustParseIndividualAddress("1.1.1"))
	temp, _ := device.NewGroupObject("temperature", "9.001", "CRWU", "1/0/2")
	_ = temp.Set(21.5)
	sw, _ := device.NewGroupObject("switch", "1.001", "CRWU", "1/0/1")
	dev.Add(temp, sw)
	s.AddDevice(dev)
	seen := make(chan server.Telegram, 64)
	s.Subscribe(func(tg server.Telegram) {
		select {
		case seen <- tg:
		default:
		}
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	host := []string{"--add-host", "host.docker.internal:host-gateway"}
	target := []string{"--target", "host.docker.internal", "--port", fmt.Sprint(port), "--nat"}

	for _, peer := range []string{"xknx", "calimero-tools", "knxd"} {
		t.Run(peer, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			if peer != "knxd" {
				d, err := runClient(ctx, peer, host, "describe", target...)
				if err == nil && !strings.Contains(fmt.Sprint(d.Data["name"]), serverName) {
					err = fmt.Errorf("name %v", d.Data["name"])
				}
				record(t, peer, "describe go-knx (NAT)", err, "")
			}
			_, err := runClient(ctx, peer, host, "connect", target...)
			record(t, peer, "tunnel connect to go-knx (NAT)", err, "")

			drain(seen)
			_, err = runClient(ctx, peer, host, "write", append(target, "--group", "1/0/1", "--dpt", "1.001", "--value", "on", "--data", "01")...)
			if err == nil {
				err = waitWrite(seen, "1/0/1", []byte{1}, 10*time.Second)
			}
			record(t, peer, "group write to go-knx", err, "")

			d, err := runClient(ctx, peer, host, "read", append(target, "--group", "1/0/2", "--dpt", "9.001", "--timeout", "8")...)
			if err == nil {
				data, _ := d.Data["data"].(string)
				if !strings.EqualFold(data, "0C33") && !strings.HasPrefix(fmt.Sprint(d.Data["value"]), "21.5") {
					err = fmt.Errorf("response %v", d.Data)
				}
			}
			record(t, peer, "group read of a go-knx device", err, "")

			// Contract 1.1: TCP, device management, busmonitor, where the
			// adapter offers them.
			tcpTarget := []string{"--target", "host.docker.internal", "--port", fmt.Sprint(port), "--tcp"}
			if peer == "xknx" || peer == "calimero-tools" {
				drain(seen)
				_, err = runClient(ctx, peer, host, "write", append(tcpTarget, "--group", "1/0/1", "--dpt", "1.001", "--value", "off", "--data", "00")...)
				if err == nil {
					err = waitWrite(seen, "1/0/1", []byte{0}, 10*time.Second)
				}
				record(t, peer, "group write to go-knx over TCP", err, "")
				d, err := runClient(ctx, peer, host, "read", append(tcpTarget, "--group", "1/0/2", "--dpt", "9.001", "--timeout", "8")...)
				if err == nil && !strings.EqualFold(fmt.Sprint(d.Data["data"]), "0C33") && !strings.HasPrefix(fmt.Sprint(d.Data["value"]), "21.5") {
					err = fmt.Errorf("response %v", d.Data)
				}
				record(t, peer, "group read of a go-knx device over TCP", err, "")
			}
			if peer == "calimero-tools" {
				d, err := runClient(ctx, peer, host, "property", append(target, "--object", "0", "--pid", "11")...)
				if err == nil && !strings.EqualFold(fmt.Sprint(d.Data["data"]), "00FA00000001") {
					err = fmt.Errorf("serial %v", d.Data)
				}
				record(t, peer, "device management: go-knx serial number", err, "")
				mon := background(t, peer, host, "busmonitor", append(target, "--count", "1", "--timeout", "20")...)
				err = s.GroupWrite(knx.MustParseGroupAddress("1/0/7"), apdu.GroupValue{Data: []byte{1}, Small: true})
				if err == nil {
					var md adapterDoc
					md, err = mon()
					frames, _ := md.Data["frames"].([]any)
					if err == nil && len(frames) == 0 {
						err = fmt.Errorf("no frame")
					}
					if err == nil {
						raw := fmt.Sprint(frames[0].(map[string]any)["raw"])
						if len(raw) < 10 || !strings.EqualFold(raw[6:10], "0807") {
							err = fmt.Errorf("frame %s", raw)
						}
					}
				}
				record(t, peer, "busmonitor of go-knx sees a telegram (TP1 frame)", err, "")
			}
		})
	}
}

func drain(ch chan server.Telegram) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func waitWrite(ch chan server.Telegram, group string, data []byte, d time.Duration) error {
	g := knx.MustParseGroupAddress(group)
	t := time.After(d)
	for {
		select {
		case tg := <-ch:
			dst, ok := tg.Frame.Group()
			if !ok || dst != g {
				continue
			}
			svc, v, err := apdu.ParseGroupValue(tg.Frame.TPDU)
			if err != nil || svc != apdu.GroupValueWriteService {
				continue
			}
			if string(v.Data) != string(data) {
				return fmt.Errorf("server saw % X, want % X", v.Data, data)
			}
			return nil
		case <-t:
			return fmt.Errorf("the server saw no write to %s", group)
		}
	}
}
