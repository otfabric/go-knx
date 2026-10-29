// SPDX-License-Identifier: MIT

package e2e

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/keyring"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

func secureServer(t *testing.T) string {
	t.Helper()
	dev, _ := secure.DeviceAuthenticationCode("trustme")
	u2, _ := secure.UserPasswordKey("secret2")
	u3, _ := secure.UserPasswordKey("secret3")
	_, addr := startServer(t, server.WithSecure(dev, map[uint8]server.SecureUser{
		2: {Key: u2, Address: knx.MustParseIndividualAddress("1.1.11")},
		3: {Key: u3},
	}))
	return addr
}

func cred(t *testing.T, user uint8, pw, dev string) tunnel.Option {
	t.Helper()
	c, err := secure.NewCredentials(user, pw, dev)
	if err != nil {
		t.Fatal(err)
	}
	return tunnel.WithSecure(c)
}

// TestSecureTunnel: KNX IP Secure tunnelling between go-knx's client and
// server.
func TestSecureTunnel(t *testing.T) {
	addr := secureServer(t)
	c := ctx(t)

	dibs, err := discovery.Describe(c, addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mustFamilies(t, dibs).Version(knxnetip.FamilySecurity); !ok {
		t.Error("security family not announced")
	}

	a, err := client.DialTunnel(c, addr, []tunnel.Option{cred(t, 2, "secret2", "trustme")})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if got := a.Link().(*tunnel.Conn).IndividualAddress(); got != knx.MustParseIndividualAddress("1.1.11") {
		t.Errorf("user 2 tunnels as %s, want its bound 1.1.11", got)
	}
	b, err := client.DialTunnel(c, addr, []tunnel.Option{cred(t, 3, "secret3", "")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	g := knx.MustParseGroupAddress("1/2/3")
	sub := b.Subscribe(4, g)
	if err := a.GroupWrite(c, g, true, client.WithDPT("1.001")); err != nil {
		t.Fatal(err)
	}
	select {
	case tg := <-sub.C():
		if v, _ := tg.Decode("1.001"); v != true {
			t.Errorf("received %v", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the second secure client saw nothing")
	}
}

func TestSecureTunnelRefused(t *testing.T) {
	addr := secureServer(t)
	c := ctx(t)
	if _, err := tunnel.Dial(c, addr, cred(t, 2, "wrong", "")); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("wrong user password: %v", err)
	}
	if _, err := tunnel.Dial(c, addr, cred(t, 9, "secret2", "")); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := tunnel.Dial(c, addr, cred(t, 2, "secret2", "wrong")); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("wrong device authentication code: %v", err)
	}
	for name, opts := range map[string][]tunnel.Option{"udp": nil, "tcp": {tunnel.WithTCP()}} {
		if _, err := tunnel.Dial(c, addr, opts...); !errors.Is(err, knx.ErrRejected) {
			t.Errorf("plain %s connection: %v", name, err)
		}
	}
	// The bound address of user 2 is refused to another request.
	if _, err := tunnel.Dial(c, addr, cred(t, 2, "secret2", ""), tunnel.WithIndividualAddress(knx.MustParseIndividualAddress("1.1.10"))); !errors.Is(err, knx.ErrRejected) {
		t.Errorf("user 2 asking for 1.1.10: %v", err)
	}
	// A plain server answers no SESSION_REQUEST.
	_, plain := startServer(t)
	if _, err := tunnel.Dial(c, plain, cred(t, 2, "secret2", ""), tunnel.WithConnectTimeout(time.Second)); err == nil {
		t.Error("secure session with a plain server")
	}
}

func TestSecureServerOptions(t *testing.T) {
	var k secure.Key
	for name, o := range map[string][]server.Option{
		"no users":    {server.WithSecure(k, nil)},
		"user 0":      {server.WithSecure(k, map[uint8]server.SecureUser{0: {}})},
		"no tcp":      {server.WithSecure(k, map[uint8]server.SecureUser{1: {}}), server.WithTCP(false)},
		"bad address": {server.WithSecure(k, map[uint8]server.SecureUser{1: {Address: knx.MustParseIndividualAddress("9.9.9")}})},
	} {
		if _, err := server.New(o...); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := tunnel.Dial(ctx(t), "127.0.0.1:1", tunnel.WithSecure(secure.Credentials{})); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("user 0: %v", err)
	}
}

// TestDataSecure: a keyring drives a secure server, two secure tunnels
// and Data Secure group communication between them.
func TestDataSecure(t *testing.T) {
	a1, a2 := knx.MustParseIndividualAddress("1.1.10"), knx.MustParseIndividualAddress("1.1.11")
	g, plainG := knx.MustParseGroupAddress("1/2/3"), knx.MustParseGroupAddress("1/2/4")
	kr := &keyring.Keyring{Project: "e2e",
		Interfaces: []keyring.Interface{
			{Type: keyring.Tunneling, IndividualAddress: a1, Host: 1, HasHost: true, UserID: 2, Password: "u2", Authentication: "dev",
				Groups: map[knx.GroupAddress][]knx.IndividualAddress{g: {a2}}},
			{Type: keyring.Tunneling, IndividualAddress: a2, Host: 1, HasHost: true, UserID: 3, Password: "u3", Authentication: "dev",
				Groups: map[knx.GroupAddress][]knx.IndividualAddress{g: {a1}}},
		},
		GroupKeys: map[knx.GroupAddress]keyring.Key{g: {0xAA, 1, 2}},
	}
	b, err := kr.Encode("pw")
	if err != nil {
		t.Fatal(err)
	}
	kr, err = keyring.Parse(b, "pw")
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := secure.DeviceAuthenticationCode("dev")
	users := map[uint8]server.SecureUser{}
	for _, itf := range kr.Tunnels(1) {
		key, _ := secure.UserPasswordKey(itf.Password)
		users[itf.UserID] = server.SecureUser{Key: key, Address: itf.IndividualAddress}
	}
	s, addr := startServer(t, server.WithSecure(dev, users))
	var seen []client.Telegram
	var mu sync.Mutex
	cancel := s.Subscribe(func(tg server.Telegram) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, client.Telegram{Frame: tg.Frame})
	})
	defer cancel()
	c := ctx(t)
	dial := func(a knx.IndividualAddress) *client.Client {
		cred, err := kr.Interface(a).Credentials()
		if err != nil {
			t.Fatal(err)
		}
		tab, err := kr.DataSecure(0)
		if err != nil {
			t.Fatal(err)
		}
		cl, err := client.DialTunnel(c, addr, []tunnel.Option{tunnel.WithSecure(cred)}, client.WithDataSecure(tab))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		return cl
	}
	c1, c2 := dial(a1), dial(a2)
	sub := c2.Subscribe(4, g, plainG)
	if err := c1.GroupWrite(c, g, 21.5, client.WithDPT("9.001")); err != nil {
		t.Fatal(err)
	}
	if err := c1.GroupWrite(c, plainG, true, client.WithDPT("1.001")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case tg := <-sub.C():
			switch tg.Group {
			case g:
				if v, _ := tg.Decode("9.001"); v != 21.5 || !tg.Secure || tg.Source != a1 {
					t.Errorf("secured telegram %v secure=%v from %s", v, tg.Secure, tg.Source)
				}
			case plainG:
				if tg.Secure {
					t.Error("plain telegram marked secure")
				}
			}
		case <-time.After(3 * time.Second):
			t.Fatal("telegram missing")
		}
	}
	// The server, like any device without the key, sees only S-A_Data.
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, tg := range seen {
		if gg, _ := tg.Frame.Group(); gg == g {
			found = true
			if !datasecure.IsSecure(tg.Frame) {
				t.Errorf("the server saw a plain telegram to the secured group: %s", tg.Frame)
			}
		}
	}
	if !found {
		t.Error("the server saw no telegram to the secured group")
	}
}
