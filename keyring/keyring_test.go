// SPDX-License-Identifier: MIT

package keyring

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
)

// The expected values are those xknx 4.0.0 reads from the same files.

func ia(t *testing.T, s string) knx.IndividualAddress {
	a, err := knx.ParseIndividualAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func ga(t *testing.T, s string) knx.GroupAddress {
	g, err := knx.ParseGroupAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func hexKey(t *testing.T, s string) (k Key) {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	copy(k[:], b)
	return k
}

func TestSecureTest(t *testing.T) {
	k, err := LoadFile("testdata/SecureTest.knxkeys", "test")
	if err != nil {
		t.Fatal(err)
	}
	if k.Project != "SecureTest" || k.Created != "2023-01-30T19:17:06" {
		t.Errorf("header %q %q", k.Project, k.Created)
	}
	if k.Backbone == nil || k.Backbone.Key != hexKey(t, "15ece0a72bc8606220a88a9f6df4487c") || k.Backbone.Latency != time.Second || k.Backbone.MulticastAddress != "224.0.23.13" {
		t.Errorf("backbone %+v", k.Backbone)
	}
	for g, want := range map[string]string{
		"0/4/0": "dfdf23a59fbb40404091d1c162087e8b", "0/4/3": "182c0b0764d29d7a9d58618c4760a80f",
		"0/4/4": "528c737e67cec46ffb3ef057978ebfff", "0/4/5": "57d4a72e9c69ae061f420022b1e69cac",
	} {
		if k.GroupKeys[ga(t, g)] != hexKey(t, want) {
			t.Errorf("group key %s %x", g, k.GroupKeys[ga(t, g)])
		}
	}
	itf := k.Interface(ia(t, "5.0.1"))
	if itf == nil || itf.UserID != 2 || itf.Password != "weinzierl_tunnel_1" || itf.Authentication != "weinzierl_auth" || itf.Host != ia(t, "5.0.0") || !itf.HasHost {
		t.Fatalf("interface 5.0.1 %+v", itf)
	}
	if s := itf.Groups[ga(t, "0/4/0")]; len(s) != 2 || s[0] != ia(t, "4.0.1") || s[1] != ia(t, "4.0.9") {
		t.Errorf("senders of 0/4/0: %v", s)
	}
	if itf := k.Interface(ia(t, "4.0.1")); itf == nil || itf.UserID != 0 || itf.Password != "" || itf.Authentication != "gmM1u'cX" {
		t.Errorf("interface 4.0.1 %+v", itf)
	}
	if n := len(k.Tunnels(ia(t, "5.0.0"))); n != 8 {
		t.Errorf("%d tunnels of 5.0.0", n)
	}
	if k.Interface(ia(t, "9.9.9")) != nil || k.Device(ia(t, "9.9.9")) != nil {
		t.Error("unknown address found")
	}
	d := k.Device(ia(t, "4.0.0"))
	if d == nil || d.ToolKey != hexKey(t, "02d40ef405b79b369c04d3928866352a") || d.ManagementPassword != "re9fIA8@" || d.Authentication != "gmM1u'cX" || d.SequenceNumber != 155806720116 {
		t.Errorf("device 4.0.0 %+v", d)
	}
	want := map[string]uint64{"4.0.9": 155806854915, "5.0.1": 0, "4.0.1": 0, "4.0.0": 155806720116, "5.0.0": 146212262858}
	s := k.Senders()
	if len(s) != len(want) {
		t.Errorf("senders %v", s)
	}
	for a, n := range want {
		if s[ia(t, a)] != n {
			t.Errorf("sender %s: %d, want %d", a, s[ia(t, a)], n)
		}
	}
}

func TestOtherFiles(t *testing.T) {
	k, err := LoadFile("testdata/testcase.knxkeys", "password")
	if err != nil {
		t.Fatal(err)
	}
	if k.Backbone.Key != hexKey(t, "cf89fd0f18f4889783c7ef44ee1f5e14") {
		t.Errorf("backbone key %x", k.Backbone.Key)
	}
	for addr, pw := range map[string]string{"1.0.1": "user1", "1.0.11": "user2", "1.0.12": "user3", "1.0.13": "user4"} {
		if itf := k.Interface(ia(t, addr)); itf == nil || itf.Password != pw || itf.Authentication != "authenticationcode" {
			t.Errorf("interface %s %+v", addr, itf)
		}
	}
	if d := k.Device(ia(t, "1.0.0")); d == nil || d.ManagementPassword != "commissioning" || d.ToolKey != hexKey(t, "9bc4fc74043a332b80baa2c8fef72d9d") || d.SequenceNumber != 133294561196 {
		t.Errorf("device %+v", d)
	}
	k, err = LoadFile("testdata/special_chars_secure_tunnel.knxkeys", "test")
	if err != nil {
		t.Fatal(err)
	}
	if itf := k.Interface(ia(t, "1.0.2")); itf == nil || itf.UserID != 2 || itf.Password != "tunnel_2" {
		t.Errorf("interface %+v", itf)
	}
	k, err = LoadFile("testdata/DataSecure_usb.knxkeys", "test")
	if err != nil {
		t.Fatal(err)
	}
	if itf := k.Interface(ia(t, "1.0.12")); itf == nil || itf.Type != USB || itf.HasHost || len(itf.Groups[ga(t, "31/7/255")]) != 1 {
		t.Errorf("USB interface %+v", itf)
	}
	if k.GroupKeys[ga(t, "31/7/255")] != hexKey(t, "d2effbdc88eb5c9a57a73b0aad64996f") || k.Backbone != nil {
		t.Errorf("group key %x", k.GroupKeys[ga(t, "31/7/255")])
	}
}

func TestWrongPassword(t *testing.T) {
	if _, err := LoadFile("testdata/SecureTest.knxkeys", "wrong"); !errors.Is(err, ErrSignature) || !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("wrong password: %v", err)
	}
	b, _ := os.ReadFile("testdata/SecureTest.knxkeys")
	b = bytes.Replace(b, []byte(`SequenceNumber="155806720116"`), []byte(`SequenceNumber="155806720117"`), 1)
	if _, err := Parse(b, "test"); !errors.Is(err, ErrSignature) {
		t.Errorf("modified file: %v", err)
	}
	if _, err := LoadFile("testdata/missing.knxkeys", "x"); err == nil {
		t.Error("missing file")
	}
}

func TestRoundTrip(t *testing.T) {
	k := &Keyring{
		Project: "go-knx & test", CreatedBy: "go-knx",
		Backbone: &Backbone{MulticastAddress: "224.0.23.12", Latency: 1500 * time.Millisecond, Key: Key{1, 2, 3}},
		Interfaces: []Interface{
			{Type: Tunneling, IndividualAddress: ia(t, "1.1.10"), Host: ia(t, "1.1.0"), HasHost: true, UserID: 2, Password: "user pässword", Authentication: "trustme",
				Groups: map[knx.GroupAddress][]knx.IndividualAddress{ga(t, "1/2/3"): {ia(t, "1.1.20"), ia(t, "1.1.21")}}},
			{Type: USB, IndividualAddress: ia(t, "1.1.11")},
		},
		GroupKeys: map[knx.GroupAddress]Key{ga(t, "1/2/3"): {9}, ga(t, "1/2/4"): {8}},
		Devices:   []Device{{IndividualAddress: ia(t, "1.1.0"), ToolKey: Key{7}, HasToolKey: true, ManagementPassword: "commissioning", Authentication: "trustme", SequenceNumber: 42}},
	}
	b, err := k.Encode("secret")
	if err != nil {
		t.Fatal(err)
	}
	if k.Created == "" || !bytes.Contains(b, []byte(`xmlns="`+Namespace+`"`)) {
		t.Fatalf("encoded:\n%s", b)
	}
	got, err := Parse(b, "secret")
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if got.Project != k.Project || *got.Backbone != *k.Backbone || len(got.Interfaces) != 2 || len(got.GroupKeys) != 2 || got.GroupKeys[ga(t, "1/2/4")] != (Key{8}) {
		t.Errorf("round trip %+v", got)
	}
	itf := got.Interface(ia(t, "1.1.10"))
	if itf.Password != "user pässword" || itf.Authentication != "trustme" || itf.UserID != 2 || len(itf.Groups[ga(t, "1/2/3")]) != 2 {
		t.Errorf("interface %+v", itf)
	}
	if d := got.Device(ia(t, "1.1.0")); d == nil || *d != k.Devices[0] {
		t.Errorf("device %+v", d)
	}
	if _, err := Parse(b, "other"); !errors.Is(err, ErrSignature) {
		t.Errorf("other password: %v", err)
	}
	if os.Getenv("KNX_KEYRING_OUT") != "" {
		_ = os.WriteFile(filepath.Join(os.Getenv("KNX_KEYRING_OUT"), "roundtrip.knxkeys"), b, 0o600)
	}
	// Passwords of every length pad to whole blocks.
	for n := 0; n < 40; n++ {
		k.Interfaces[0].Password = strings.Repeat("x", n)
		b, err := k.Encode("p")
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(b, "p")
		if err != nil || got.Interfaces[0].Password != k.Interfaces[0].Password {
			t.Fatalf("password of %d: %v", n, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	for name, doc := range map[string]string{
		"not xml":    "<Keyring",
		"empty":      "",
		"root":       `<Other Signature="AAAA" />`,
		"two roots":  `<Keyring /><Keyring />`,
		"bad base64": `<Keyring Signature="%%%" />`,
		"unbalanced": `</Keyring>`,
		"long attr":  `<Keyring Signature="AAAA" A="` + strings.Repeat("a", 300) + `" />`,
	} {
		if _, err := Parse([]byte(doc), "x"); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// signed returns a document with a valid signature for password "x".
func signed(t *testing.T, body string) []byte {
	t.Helper()
	root, err := parseTree([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	s, err := signature(root, passwordHash("x"))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(body, `Signature=""`, `Signature="`+base64.StdEncoding.EncodeToString(s)+`"`, 1))
}

func TestMalformedValues(t *testing.T) {
	for name, doc := range map[string]string{
		"latency":     `<Keyring Signature=""><Backbone Latency="x" /></Keyring>`,
		"backbone":    `<Keyring Signature=""><Backbone Key="%%" /></Keyring>`,
		"key length":  `<Keyring Signature=""><Backbone Key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" /></Keyring>`,
		"block":       `<Keyring Signature=""><Backbone Key="AAAA" /></Keyring>`,
		"iface addr":  `<Keyring Signature=""><Interface IndividualAddress="x" /></Keyring>`,
		"host":        `<Keyring Signature=""><Interface IndividualAddress="1.1.1" Host="x" /></Keyring>`,
		"user":        `<Keyring Signature=""><Interface IndividualAddress="1.1.1" UserID="300" /></Keyring>`,
		"password":    `<Keyring Signature=""><Interface IndividualAddress="1.1.1" Password="%%" /></Keyring>`,
		"auth":        `<Keyring Signature=""><Interface IndividualAddress="1.1.1" Authentication="AAAAAAAAAAAAAAAAAAAAAA==" /></Keyring>`,
		"iface group": `<Keyring Signature=""><Interface IndividualAddress="1.1.1"><Group Address="x" /></Interface></Keyring>`,
		"sender":      `<Keyring Signature=""><Interface IndividualAddress="1.1.1"><Group Address="1" Senders="x" /></Interface></Keyring>`,
		"group":       `<Keyring Signature=""><GroupAddresses><Group Address="70000" /></GroupAddresses></Keyring>`,
		"group key":   `<Keyring Signature=""><GroupAddresses><Group Address="1" Key="%%" /></GroupAddresses></Keyring>`,
		"device":      `<Keyring Signature=""><Devices><Device IndividualAddress="x" /></Devices></Keyring>`,
		"tool key":    `<Keyring Signature=""><Devices><Device IndividualAddress="1.1.1" ToolKey="%%" /></Devices></Keyring>`,
		"mgmt":        `<Keyring Signature=""><Devices><Device IndividualAddress="1.1.1" ManagementPassword="%%" /></Devices></Keyring>`,
		"dev auth":    `<Keyring Signature=""><Devices><Device IndividualAddress="1.1.1" Authentication="%%" /></Devices></Keyring>`,
		"sequence":    `<Keyring Signature=""><Devices><Device IndividualAddress="1.1.1" SequenceNumber="-1" /></Devices></Keyring>`,
	} {
		if _, err := Parse(signed(t, doc), "x"); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Unknown elements are skipped; group addresses may be written 1/2/3.
	k, err := Parse(signed(t, `<Keyring Signature=""><Other /><GroupAddresses><Other /><Group Address="1/2/3" /></GroupAddresses><Devices><Other /></Devices><Interface IndividualAddress="1.1.1"><Other /></Interface></Keyring>`), "x")
	if err != nil || len(k.GroupKeys) != 0 || len(k.Interfaces) != 1 {
		t.Errorf("skip unknown: %v %+v", err, k)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("no randomness") }

func TestEncodeErrors(t *testing.T) {
	k := &Keyring{Interfaces: []Interface{{IndividualAddress: 1, Password: "x"}}}
	if _, err := k.encode("p", failReader{}); err == nil {
		t.Error("interface password without randomness")
	}
	k = &Keyring{Devices: []Device{{IndividualAddress: 1, Authentication: "x"}}}
	if _, err := k.encode("p", failReader{}); err == nil {
		t.Error("device password without randomness")
	}
	k = &Keyring{Project: strings.Repeat("p", 300)}
	if _, err := k.Encode("p"); !errors.Is(err, knx.ErrMalformed) {
		t.Errorf("long project name: %v", err)
	}
	if _, err := Load(failReader{}, "p"); err == nil {
		t.Error("read error")
	}
	if _, err := Load(strings.NewReader(""), "p"); !errors.Is(err, knx.ErrMalformed) {
		t.Errorf("empty: %v", err)
	}
}

func TestLookups(t *testing.T) {
	k, err := LoadFile("testdata/SecureTest.knxkeys", "test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := k.Interface(ia(t, "5.0.1")).Credentials()
	if err != nil || c.UserID != 2 || c.DeviceCode == nil {
		t.Fatalf("credentials %+v %v", c, err)
	}
	if _, err := k.Interface(ia(t, "4.0.1")).Credentials(); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("interface without user: %v", err)
	}
	tab, err := k.DataSecure(1)
	if err != nil || !tab.Secured(ga(t, "0/4/0")) || tab.Sequence() != 1 {
		t.Errorf("data secure %v", err)
	}
	if key, lat, ok := k.BackboneKey(); !ok || lat != time.Second || key[0] != 0x15 {
		t.Errorf("backbone %x %v %v", key, lat, ok)
	}
	if _, _, ok := (&Keyring{}).BackboneKey(); ok {
		t.Error("backbone of an empty keyring")
	}
}
