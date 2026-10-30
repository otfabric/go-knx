// SPDX-License-Identifier: MIT

//go:build interop

package interop

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/devmgmt"
	"github.com/otfabric/go-knx/keyring"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

// The KNX Secure test profile of knx-interop (contract 1.2), taken from
// the adapter images: public test values.
const (
	profileKeyringPassword = "knx-interop"
	profileHost            = "1.1.0"
)

// profileKeyring copies the profile's keyring out of an adapter image.
func profileKeyring(t *testing.T) *keyring.Keyring {
	t.Helper()
	b := docker(t, "run", "--rm", "--entrypoint", "cat", image("xknx"), "/adapter/common/secure/knx-interop.knxkeys")
	p := filepath.Join(t.TempDir(), "profile.knxkeys")
	if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := keyring.LoadFile(p, profileKeyringPassword)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// TestGoKNXSecureServer: xknx and Calimero tools open KNX IP Secure
// sessions to go-knx's secure server, with Data Secure.
func TestGoKNXSecureServer(t *testing.T) {
	requireDocker(t)
	kr := profileKeyring(t)
	host := knx.MustParseIndividualAddress(profileHost)
	users := map[uint8]server.SecureUser{}
	var devPassword string
	for _, itf := range kr.Tunnels(host) {
		k, _ := secure.UserPasswordKey(itf.Password)
		users[itf.UserID] = server.SecureUser{Key: k, Address: itf.IndividualAddress}
		devPassword = itf.Authentication
	}
	if d := kr.Device(host); d != nil {
		k, _ := secure.UserPasswordKey(d.ManagementPassword)
		users[1] = server.SecureUser{Key: k}
	}
	dev, _ := secure.DeviceAuthenticationCode(devPassword)
	port := freePort(t)
	var tunnels []knx.IndividualAddress
	for i := 10; i < 18; i++ {
		tunnels = append(tunnels, knx.MustParseIndividualAddress(fmt.Sprintf("1.1.%d", i)))
	}
	s, err := server.New(server.WithListenAddr(fmt.Sprintf("0.0.0.0:%d", port)), server.WithDiscovery(false), server.WithName(serverName),
		server.WithIndividualAddress(host), server.WithTunnelAddresses(tunnels...), server.WithSecure(dev, users))
	if err != nil {
		t.Fatal(err)
	}
	d := device.New("dev", knx.MustParseIndividualAddress("1.1.1"))
	temp, _ := device.NewGroupObject("temperature", "9.001", "CRWU", "1/0/2")
	_ = temp.Set(21.5)
	sw, _ := device.NewGroupObject("switch", "1.001", "CRWU", "1/0/1")
	d.Add(temp, sw)
	s.AddDevice(d)
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
	tab, err := kr.DataSecure(1)
	if err != nil {
		t.Fatal(err)
	}
	host2 := []string{"--add-host", "host.docker.internal:host-gateway"}
	target := []string{"--target", "host.docker.internal", "--port", fmt.Sprint(port), "--secure", "--user", "2"}

	for _, peer := range []string{"xknx", "calimero-tools"} {
		t.Run(peer, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			d, err := runClient(ctx, peer, host2, "connect", target...)
			if err == nil && fmt.Sprint(d.Data["address"]) != "1.1.10" {
				err = fmt.Errorf("user 2 tunnels as %v, not 1.1.10", d.Data["address"])
			}
			record(t, peer, "secure session to go-knx (user 2, bound address)", err, "")

			drain(seen)
			_, err = runClient(ctx, peer, host2, "write", append(target, "--group", "1/0/1", "--dpt", "1.001", "--value", "on", "--data", "01")...)
			if err == nil {
				err = waitWrite(seen, "1/0/1", []byte{1}, 10*time.Second)
			}
			record(t, peer, "secure group write to go-knx", err, "")

			d, err = runClient(ctx, peer, host2, "read", append(target, "--group", "1/0/2", "--dpt", "9.001", "--timeout", "8")...)
			if err == nil && !strings.EqualFold(fmt.Sprint(d.Data["data"]), "0C33") && !strings.HasPrefix(fmt.Sprint(d.Data["value"]), "21.5") {
				err = fmt.Errorf("response %v", d.Data)
			}
			record(t, peer, "secure group read of a go-knx device", err, "")

			if peer == "xknx" {
				// Data Secure: the server forwards S-A_Data; the profile's
				// key decrypts it to the written value.
				drain(seen)
				_, err = runClient(ctx, peer, host2, "write", append(target, "--group", "1/3/2", "--dpt", "9.001", "--value", "21.5", "--data", "0C33")...)
				if err == nil {
					err = waitSecureWrite(seen, tab, "1/3/2", []byte{0x0C, 0x33}, 10*time.Second)
				}
				record(t, peer, "Data Secure group write through go-knx (decrypted with the profile key)", err, "")
			}
			if peer == "calimero-tools" {
				d, err := runClient(ctx, peer, host2, "property", "--target", "host.docker.internal", "--port", fmt.Sprint(port), "--secure", "--user", "1", "--object", "0", "--pid", "11")
				if err == nil && !strings.EqualFold(fmt.Sprint(d.Data["data"]), "00FA00000001") {
					err = fmt.Errorf("serial %v", d.Data)
				}
				record(t, peer, "secure device management: go-knx serial number (user 1)", err, "")
			}
		})
	}
}

// waitSecureWrite waits for an S-A_Data write to group g and checks its
// decrypted value.
func waitSecureWrite(seen chan server.Telegram, tab *datasecure.Table, g string, data []byte, d time.Duration) error {
	ga := knx.MustParseGroupAddress(g)
	timeout := time.After(d)
	for {
		select {
		case tg := <-seen:
			if dst, ok := tg.Frame.Group(); !ok || dst != ga {
				continue
			}
			if !datasecure.IsSecure(tg.Frame) {
				return fmt.Errorf("plain telegram to the secured group: %s", tg.Frame)
			}
			tab.AddSender(tg.Frame.Source, 0)
			plain, err := tab.Incoming(tg.Frame)
			if err != nil {
				return err
			}
			if got := plain.TPDU[2:]; string(got) != string(data) {
				return fmt.Errorf("decrypted % X, want % X", got, data)
			}
			return nil
		case <-timeout:
			return fmt.Errorf("no write to %s", g)
		}
	}
}

// TestGoKNXSecureClient: go-knx's secure client against Calimero's secure
// server.
func TestGoKNXSecureClient(t *testing.T) {
	requireDocker(t)
	kr := profileKeyring(t)
	net := network(t)
	id := docker(t, "run", "-d", "--network", net, "-p", "127.0.0.1::3671/tcp", "-p", "127.0.0.1::3671/udp", image("calimero-server"), "server", "--name", serverName, "--secure")
	name := strings.TrimSpace(docker(t, "inspect", "-f", "{{.Name}}", id))[1:]
	addr := strings.Split(docker(t, "port", id, "3671/tcp"), "\n")[0]
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cred2, err := kr.Interface(knx.MustParseIndividualAddress("1.1.10")).Credentials()
	if err != nil {
		t.Fatal(err)
	}
	tab, _ := kr.DataSecure(0)
	var c *client.Client
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if c, err = client.DialTunnel(ctx, addr, []tunnel.Option{tunnel.WithSecure(cred2)}, client.WithDataSecure(tab)); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	peer := "calimero-server"
	record(t, peer, "secure session (user 2)", err, "")
	if err != nil {
		t.FailNow()
	}
	defer c.Close()
	if a := c.Link().(*tunnel.Conn).IndividualAddress(); a != knx.MustParseIndividualAddress("1.1.10") {
		record(t, peer, "user 2 bound to 1.1.10", fmt.Errorf("address %s", a), "")
	}

	obs := background(t, "xknx", []string{"--network", net}, "monitor", "--target", name, "--secure", "--user", "3", "--count", "1", "--timeout", "20")
	err = c.GroupWrite(ctx, knx.MustParseGroupAddress("1/0/1"), true)
	record(t, peer, "secure group write confirmed", err, "")
	d, oerr := obs()
	if oerr == nil {
		oerr = expectTelegram(d, "1/0/1", "write", "01")
	}
	record(t, peer, "secure group write seen by xknx (user 3)", oerr, "")

	obs = background(t, "xknx", []string{"--network", net}, "monitor", "--target", name, "--secure", "--user", "3", "--count", "1", "--timeout", "20")
	err = c.GroupWrite(ctx, knx.MustParseGroupAddress("1/3/2"), 21.5, client.WithDPT("9.001"))
	d, oerr = obs()
	if err == nil {
		err = oerr
	}
	if err == nil {
		err = expectTelegram(d, "1/3/2", "write", "0C33")
	}
	record(t, peer, "Data Secure group write decrypted by xknx", err, "")
	_ = c.Close()

	// Device management as the management user.
	cred1, err := secure.NewCredentials(1, kr.Device(knx.MustParseIndividualAddress(profileHost)).ManagementPassword, cred2Password(kr))
	if err == nil {
		var dm *devmgmt.Conn
		if dm, err = devmgmt.Dial(ctx, addr, tunnel.WithSecure(cred1)); err == nil {
			var b []byte
			b, err = dm.PropRead(ctx, devmgmt.ObjectDevice, 1, 11, 1, 1)
			if err == nil && len(b) != 6 {
				err = fmt.Errorf("serial % X", b)
			}
			_ = dm.Close()
		}
	}
	record(t, peer, "secure device management: serial number (user 1)", err, "")

	// A plain tunnel is refused.
	_, err = tunnel.Dial(ctx, addr, tunnel.WithTCP())
	if err == nil {
		err = fmt.Errorf("a plain tunnel was accepted")
	} else {
		err = nil
	}
	record(t, peer, "plain connection refused", err, "")
}

func cred2Password(kr *keyring.Keyring) string {
	return kr.Interface(knx.MustParseIndividualAddress("1.1.10")).Authentication
}
