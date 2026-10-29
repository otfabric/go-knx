// SPDX-License-Identifier: MIT

package knxnetip

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/otfabric/go-knx"
)

// frame builds a KNXnet/IP frame of service t around body (hex, spaces
// allowed) with a correct header.
func frame(tb testing.TB, t ServiceType, body string) []byte {
	tb.Helper()
	p := mustHex(tb, strings.ReplaceAll(body, " ", ""))
	return append(AppendHeader(nil, t, len(p)), p...)
}

const (
	hpaiOK  = "08 01 c0a80102 c351"
	mac16   = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	key32   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	devInfo = "36 01 02 00 1101 0000 00fa12345678 e000170c 00246d010203" + "4b4e5820495020526f75746572" + "0000000000000000000000000000000000"
)

func TestParseMalformed(t *testing.T) {
	cases := []struct {
		name string
		svc  ServiceType
		body string
	}{
		{"search request short HPAI", SearchRequestType, "08 01 c0a8"},
		{"search request HPAI length octet", SearchRequestType, "07 01 c0a80102 c351"},
		{"search request HPAI protocol", SearchRequestType, "08 03 c0a80102 c351"},
		{"search request trailing", SearchRequestType, hpaiOK + "00"},
		{"description request trailing", DescriptionRequestType, hpaiOK + "0000"},
		{"search request ext bad HPAI", SearchRequestExtType, "08"},
		{"search request ext SRP one octet", SearchRequestExtType, hpaiOK + "02"},
		{"search request ext SRP length 1", SearchRequestExtType, hpaiOK + "01 02"},
		{"search request ext SRP overrun", SearchRequestExtType, hpaiOK + "05 02 00"},
		{"search response bad HPAI", SearchResponseType, "08 09 00000000 0000"},
		{"search response bad DIB", SearchResponseType, hpaiOK + "01"},
		{"description response DIB length 0", DescriptionResponseType, "00 01"},
		{"description response DIB overrun", DescriptionResponseType, "08 02 0201"},
		{"description response device info length", DescriptionResponseType, "04 01 0200"},
		{"description response families odd", DescriptionResponseType, "05 02 0201 00"},
		{"description response IP config length", DescriptionResponseType, "04 03 0000"},
		{"description response IP current config length", DescriptionResponseType, "04 04 0000"},
		{"description response KNX addresses odd", DescriptionResponseType, "05 05 1101 00"},
		{"description response KNX addresses empty", DescriptionResponseType, "02 05"},
		{"description response tunnelling info short", DescriptionResponseType, "02 07"},
		{"description response tunnelling info slot", DescriptionResponseType, "06 07 00fe 1101"},
		{"description response ext device info length", DescriptionResponseType, "04 08 0000"},
		{"description response manufacturer data short", DescriptionResponseType, "03 fe 00"},
		{"connect request bad control", ConnectRequestType, "08"},
		{"connect request bad data", ConnectRequestType, hpaiOK + "08"},
		{"connect request no CRI", ConnectRequestType, hpaiOK + hpaiOK},
		{"connect request CRI length mismatch", ConnectRequestType, hpaiOK + hpaiOK + "05 04 02 00"},
		{"connect request tunnel CRI length 5", ConnectRequestType, hpaiOK + hpaiOK + "05 04 02 00 11"},
		{"connect request device management CRI length 4", ConnectRequestType, hpaiOK + hpaiOK + "04 03 0000"},
		{"connect response short", ConnectResponseType, "15"},
		{"connect response bad HPAI", ConnectResponseType, "15 00 08 01"},
		{"connect response no CRD", ConnectResponseType, "15 00" + hpaiOK},
		{"connect response tunnel CRD length", ConnectResponseType, "15 00" + hpaiOK + "06 04 1101 0000"},
		{"connect response device management CRD length", ConnectResponseType, "15 00" + hpaiOK + "04 03 0000"},
		{"connect response CRD length mismatch", ConnectResponseType, "15 00" + hpaiOK + "05 04 1101"},
		{"connectionstate request short", ConnectionStateRequestType, "15 00 08 01"},
		{"connectionstate request bad HPAI", ConnectionStateRequestType, "15 00 08 05 c0a80102 c351"},
		{"disconnect request long", DisconnectRequestType, "15 00" + hpaiOK + "00"},
		{"connectionstate response long", ConnectionStateResponseType, "15 00 00"},
		{"disconnect response short", DisconnectResponseType, "15"},
		{"tunnelling request connection header short", TunnellingRequestType, "04 15 00"},
		{"tunnelling request connection header length", TunnellingRequestType, "05 15 00 00 11 00"},
		{"tunnelling request cEMI short", TunnellingRequestType, "04 15 00 00 11"},
		{"device configuration request cEMI empty", DeviceConfigurationRequestType, "04 15 00 00"},
		{"tunnelling ack trailing", TunnellingAckType, "04 15 00 00 00"},
		{"tunnelling ack short", TunnellingAckType, "04 15 00"},
		{"device configuration ack header length", DeviceConfigurationAckType, "03 15 00 00"},
		{"tunnelling feature short", TunnellingFeatureResponseType, "04 15 00 00 03"},
		{"tunnelling feature bad header", TunnellingFeatureInfoType, "04 15"},
		{"tunnelling feature get with value", TunnellingFeatureGetType, "04 15 00 00 03 00 01"},
		{"routing indication short", RoutingIndicationType, "29"},
		{"routing system broadcast empty", RoutingSystemBroadcastType, ""},
		{"routing lost message length octet", RoutingLostMessageType, "05 00 0005"},
		{"routing lost message short", RoutingLostMessageType, "04 00 00"},
		{"routing busy length octet", RoutingBusyType, "04 00 0064 0000"},
		{"routing busy long", RoutingBusyType, "06 00 0064 0000 00"},
		{"secure wrapper short", SecureWrapperType, "0001 000000000001 00fa12345678 0000 010203040506" + mac16[:30]},
		{"session request bad HPAI", SessionRequestType, "07"},
		{"session request short key", SessionRequestType, hpaiOK + key32[:62]},
		{"session response short", SessionResponseType, "0001" + key32 + mac16[:30]},
		{"session authenticate long", SessionAuthenticateType, "0001" + mac16 + "00"},
		{"session status long", SessionStatusType, "00 00 00"},
		{"timer notify short", TimerNotifyType, "000000000102 00fa12345678 0000" + mac16[:30]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := frame(t, c.svc, c.body)
			m, err := Parse(b)
			if !errors.Is(err, knx.ErrMalformed) {
				t.Fatalf("Parse(% X) = %#v, %v; want ErrMalformed", b, m, err)
			}
			if m != nil {
				t.Fatalf("message %#v returned with error", m)
			}
		})
	}
}

func TestParseHeaderErrors(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want error
	}{
		{"empty", "", knx.ErrMalformed},
		{"five octets", "0610020100", knx.ErrMalformed},
		{"header length", "0510 0201 000e", knx.ErrMalformed},
		{"version 2.0", "0620 0201 0006", knx.ErrUnsupported},
		{"total shorter than header", "0610 0201 0005", knx.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := mustHex(t, strings.ReplaceAll(c.hex, " ", ""))
			if _, err := ParseHeader(b); !errors.Is(err, c.want) {
				t.Fatalf("ParseHeader: %v, want %v", err, c.want)
			}
			if _, err := Parse(b); !errors.Is(err, c.want) {
				t.Fatalf("Parse: %v, want %v", err, c.want)
			}
		})
	}
	h, err := ParseHeader(mustHex(t, "061004200015ffff"))
	if err != nil || h.Service != TunnellingRequestType || h.Length != 0x15 {
		t.Fatalf("ParseHeader = %+v, %v", h, err)
	}
}

func TestParseLengthMismatch(t *testing.T) {
	b := frame(t, ConnectionStateResponseType, "15 00")
	for _, n := range []int{len(b) - 1, len(b) + 1} {
		var c []byte
		if n < len(b) {
			c = b[:n]
		} else {
			c = append(append([]byte(nil), b...), 0)
		}
		if _, err := Parse(c); !errors.Is(err, knx.ErrMalformed) {
			t.Fatalf("%d of %d octets: %v", n, len(b), err)
		}
	}
	// A frame longer than MaxFrameLen is refused even with a matching length.
	big := frame(t, 0x0601, strings.Repeat("00", MaxFrameLen))
	if _, err := Parse(big); !errors.Is(err, knx.ErrMalformed) {
		t.Fatalf("oversized frame: %v", err)
	}
}

func TestAppendTooLong(t *testing.T) {
	prefix := []byte{0xAA}
	out, err := Append(prefix, &Unknown{Type: 0x0601, Body: make([]byte, MaxFrameLen-HeaderLen+1)})
	if err == nil || !errors.Is(err, errTooLong) {
		t.Fatalf("Append oversized: %v", err)
	}
	if !bytes.Equal(out, prefix) {
		t.Fatalf("Append did not restore the buffer: % X", out)
	}
	ok, err := Append(prefix, &Unknown{Type: 0x0601, Body: make([]byte, MaxFrameLen-HeaderLen)})
	if err != nil || len(ok) != 1+MaxFrameLen {
		t.Fatalf("Append of exactly MaxFrameLen: %d, %v", len(ok), err)
	}
	if m, err := Parse(ok[1:]); err != nil || m.(*Unknown).Type != 0x0601 {
		t.Fatalf("Parse of MaxFrameLen frame: %v", err)
	}
}

func TestUnknownServicePreserved(t *testing.T) {
	// A known family with an unassigned identifier, and an unknown family.
	for _, svc := range []ServiceType{0x0426, 0x0740, 0xFFFF} {
		b := frame(t, svc, "de ad be ef")
		m, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		u, ok := m.(*Unknown)
		if !ok || u.Type != svc || !bytes.Equal(u.Body, []byte{0xde, 0xad, 0xbe, 0xef}) {
			t.Fatalf("Parse(%s) = %#v", svc, m)
		}
		if svc.Known() {
			t.Fatalf("%s reported known", svc)
		}
		out, _ := Marshal(m)
		if !bytes.Equal(out, b) {
			t.Fatalf("re-encode % X, want % X", out, b)
		}
	}
	// The body of an Unknown does not alias the input.
	b := frame(t, 0x0601, "01")
	m, _ := Parse(b)
	b[6] = 0x99
	if m.(*Unknown).Body[0] != 0x01 {
		t.Fatal("Unknown.Body aliases the input")
	}
}

func TestParseCopiesCEMI(t *testing.T) {
	b := frame(t, TunnellingRequestType, "04 01 02 00 11 00 bce0 0000 0a03 01 0081")
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	b[10] = 0xFF
	if m.(*TunnellingRequest).CEMI[0] != 0x11 {
		t.Fatal("TunnellingRequest.CEMI aliases the input")
	}
}

func TestReservedOctetsAreNotPreserved(t *testing.T) {
	// The reserved octet of the connection header (and of other structures)
	// is ignored on decode and written as 0: encoding is canonical.
	in := frame(t, TunnellingRequestType, "04 01 02 ff 11 00 bce0 0000 0a03 01 0081")
	m, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Marshal(m)
	want := frame(t, TunnellingRequestType, "04 01 02 00 11 00 bce0 0000 0a03 01 0081")
	if !bytes.Equal(out, want) {
		t.Fatalf("got % X, want % X", out, want)
	}
}

func TestReadFrame(t *testing.T) {
	good := frame(t, ConnectionStateResponseType, "15 00")
	if _, err := ReadFrame(bytes.NewReader(nil)); err != io.EOF {
		t.Fatalf("empty stream: %v, want io.EOF", err)
	}
	if _, err := ReadFrame(bytes.NewReader(good[:3])); err != io.ErrUnexpectedEOF {
		t.Fatalf("partial header: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(good[:7])); err != io.ErrUnexpectedEOF {
		t.Fatalf("partial body: %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadFrame(bytes.NewReader(good[:6])); err != io.ErrUnexpectedEOF {
		t.Fatalf("missing body: %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadFrame(bytes.NewReader(mustHex(t, "0620020800080000"))); !errors.Is(err, knx.ErrUnsupported) {
		t.Fatalf("bad version: %v", err)
	}
	// A huge length is refused before the body is read.
	r := &countingReader{r: bytes.NewReader(append(mustHex(t, "06100601ffff"), make([]byte, 100)...))}
	if _, err := ReadFrame(r); !errors.Is(err, knx.ErrMalformed) {
		t.Fatalf("too long: %v", err)
	}
	if r.n != HeaderLen {
		t.Fatalf("read %d octets of an oversized frame, want only the header", r.n)
	}
	// Two frames back to back.
	two := bytes.NewReader(append(append([]byte(nil), good...), good...))
	for i := 0; i < 2; i++ {
		b, err := ReadFrame(two)
		if err != nil || !bytes.Equal(b, good) {
			t.Fatalf("frame %d: % X, %v", i, b, err)
		}
	}
	// A header-only frame has no body to read.
	b, err := ReadFrame(bytes.NewReader(mustHex(t, "061077770006")))
	if err != nil || len(b) != 6 {
		t.Fatalf("header-only frame: % X, %v", b, err)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestAppendHeader(t *testing.T) {
	got := AppendHeader([]byte{0xFF}, SearchRequestType, 8)
	if want := mustHex(t, "ff06100201000e"); !bytes.Equal(got, want) {
		t.Fatalf("AppendHeader = % X, want % X", got, want)
	}
}

func TestServiceType(t *testing.T) {
	cases := []struct {
		t      ServiceType
		name   string
		family ServiceFamilyID
	}{
		{SearchRequestType, "SEARCH_REQUEST", FamilyCore},
		{TunnellingRequestType, "TUNNELLING_REQUEST", FamilyTunnelling},
		{DeviceConfigurationAckType, "DEVICE_CONFIGURATION_ACK", FamilyDeviceManagement},
		{RoutingBusyType, "ROUTING_BUSY", FamilyRouting},
		{TimerNotifyType, "TIMER_NOTIFY", FamilySecurity},
		{0x0601, "0x0601", FamilyRemoteLogging},
	}
	for _, c := range cases {
		if c.t.String() != c.name || c.t.Family() != c.family || c.t.Known() != !strings.HasPrefix(c.name, "0x") {
			t.Errorf("%04X: %q %v %v", uint16(c.t), c.t.String(), c.t.Family(), c.t.Known())
		}
	}
	// Every named service type is decoded by ParseBody (not as Unknown).
	for st := range serviceNames {
		m, _ := ParseBody(st, nil)
		if _, unknown := m.(*Unknown); unknown {
			t.Errorf("%s decodes as Unknown", st)
		}
	}
}

func TestStrings(t *testing.T) {
	cases := []struct{ got, want string }{
		{IPv4UDP.String(), "UDP"}, {IPv4TCP.String(), "TCP"}, {HostProtocol(9).String(), "0x09"},
		{DeviceManagementConnection.String(), "DEVICE_MGMT_CONNECTION"}, {TunnelConnection.String(), "TUNNEL_CONNECTION"},
		{RemoteLoggingConnection.String(), "REMLOG_CONNECTION"}, {RemoteConfigConnection.String(), "REMCONF_CONNECTION"},
		{ObjectServerConnection.String(), "OBJSVR_CONNECTION"}, {ConnectionType(0x42).String(), "0x42"},
		{TunnelLinkLayer.String(), "TUNNEL_LINKLAYER"}, {TunnelRaw.String(), "TUNNEL_RAW"},
		{TunnelBusmonitor.String(), "TUNNEL_BUSMONITOR"}, {TunnelLayer(1).String(), "0x01"},
		{DIBDeviceInfo.String(), "DEVICE_INFO"}, {DIBSupportedServices.String(), "SUPP_SVC_FAMILIES"},
		{DIBIPConfig.String(), "IP_CONFIG"}, {DIBIPCurrentConfig.String(), "IP_CUR_CONFIG"},
		{DIBKNXAddresses.String(), "KNX_ADDRESSES"}, {DIBSecuredServices.String(), "SECURED_SERVICE_FAMILIES"},
		{DIBTunnellingInfo.String(), "TUNNELLING_INFO"}, {DIBExtendedDeviceInfo.String(), "EXTENDED_DEVICE_INFO"},
		{DIBManufacturerData.String(), "MFR_DATA"}, {DIBType(0x99).String(), "0x99"},
		{MediumTP1.String(), "TP1"}, {MediumPL110.String(), "PL110"}, {MediumRF.String(), "RF"},
		{MediumIP.String(), "KNX IP"}, {Medium(0x01).String(), "0x01"},
		{FamilyCore.String(), "Core"}, {FamilyDeviceManagement.String(), "DeviceManagement"},
		{FamilyTunnelling.String(), "Tunnelling"}, {FamilyRouting.String(), "Routing"},
		{FamilyRemoteLogging.String(), "RemoteLogging"}, {FamilyRemoteConfig.String(), "RemoteConfigurationAndDiagnosis"},
		{FamilyObjectServer.String(), "ObjectServer"}, {FamilySecurity.String(), "Security"},
		{ServiceFamilyID(0x0A).String(), "0x0A"},
		{StatusNoMoreConnections.String(), "E_NO_MORE_CONNECTIONS"}, {StatusNoError.String(), "E_NO_ERROR"},
		{Status(0x99).String(), "0x99"},
		{udp("192.168.1.10:3671").String(), "UDP 192.168.1.10:3671"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

func TestStatusError(t *testing.T) {
	cases := []struct {
		st   Status
		busy bool
	}{
		{StatusNoMoreConnections, true},
		{StatusNoMoreUniqueConns, true},
		{StatusConnectionType, false},
		{StatusConnectionID, false},
	}
	for _, c := range cases {
		var err error = &StatusError{Service: ConnectResponseType, Status: c.st}
		wrapped := errors.Join(errors.New("context"), err)
		if !errors.Is(wrapped, knx.ErrRejected) {
			t.Errorf("%s: not ErrRejected", c.st)
		}
		if errors.Is(wrapped, knx.ErrBusy) != c.busy {
			t.Errorf("%s: ErrBusy = %v", c.st, !c.busy)
		}
		if errors.Is(wrapped, knx.ErrTimeout) {
			t.Errorf("%s: matches ErrTimeout", c.st)
		}
		if st, ok := StatusOf(wrapped); !ok || st != c.st {
			t.Errorf("StatusOf = %v, %v", st, ok)
		}
	}
	e := &StatusError{Service: ConnectResponseType, Status: StatusNoMoreConnections}
	if want := "knxnetip: CONNECT_RESPONSE: E_NO_MORE_CONNECTIONS (0x24)"; e.Error() != want {
		t.Fatalf("Error() = %q", e.Error())
	}
	if _, ok := StatusOf(errors.New("x")); ok {
		t.Fatal("StatusOf of a plain error")
	}
}

func TestHPAI(t *testing.T) {
	cases := []struct {
		in        netip.AddrPort
		want      HPAI
		routeBack bool
	}{
		{ap("192.168.1.10:3671"), udp("192.168.1.10:3671"), false},
		{ap("[::ffff:192.168.1.10]:3671"), udp("192.168.1.10:3671"), false},
		{ap("[2001:db8::1]:3671"), RouteBackHPAI(), true},
		{netip.AddrPort{}, RouteBackHPAI(), true},
		{ap("192.168.1.10:0"), udp("192.168.1.10:0"), true},
		{ap("0.0.0.0:3671"), udp("0.0.0.0:3671"), true},
	}
	for _, c := range cases {
		h := NewHPAI(c.in)
		if h != c.want || h.IsRouteBack() != c.routeBack {
			t.Errorf("NewHPAI(%v) = %v (route back %v)", c.in, h, h.IsRouteBack())
		}
	}
	if !(HPAI{}).IsRouteBack() {
		t.Error("zero HPAI is not route back")
	}
	if tcp := TCPHPAI(); tcp.Protocol != IPv4TCP || !tcp.IsRouteBack() {
		t.Errorf("TCPHPAI = %v", tcp)
	}
	// An HPAI holding an IPv6 address (not constructible on the wire)
	// encodes as 0.0.0.0.
	got := HPAI{Protocol: IPv4UDP, Addr: ap("[2001:db8::1]:5")}.AppendTo(nil)
	if want := mustHex(t, "0801000000000005"); !bytes.Equal(got, want) {
		t.Errorf("IPv6 HPAI = % X", got)
	}
	h, rest, err := ParseHPAI(mustHex(t, "0802c0a80101abcd"+"ff"))
	if err != nil || h != (HPAI{IPv4TCP, ap("192.168.1.1:43981")}) || !bytes.Equal(rest, []byte{0xff}) {
		t.Errorf("ParseHPAI = %v % X %v", h, rest, err)
	}
}

func TestCRIandCRD(t *testing.T) {
	for _, b := range [][]byte{nil, {1}, {3, 4}} {
		if _, err := ParseCRI(b); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("ParseCRI(% X): %v", b, err)
		}
		if _, err := ParseCRD(b); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("ParseCRD(% X): %v", b, err)
		}
	}
	c := CRI{Type: ObjectServerConnection}
	if got := c.AppendTo(nil); !bytes.Equal(got, []byte{2, 8}) {
		t.Errorf("empty-data CRI = % X", got)
	}
	d := CRD{Type: RemoteConfigConnection, Data: []byte{9, 9}}
	b := d.AppendTo(nil)
	back, err := ParseCRD(b)
	if err != nil || back.Type != RemoteConfigConnection || !bytes.Equal(back.Data, d.Data) {
		t.Errorf("CRD round trip: %+v %v", back, err)
	}
}

func TestDeviceInfo(t *testing.T) {
	d := DeviceInfo{Status: 0x01, Serial: [6]byte{0x00, 0xC5, 0x01, 0x02, 0x03, 0x04}, Name: "Bürø ☃ " + strings.Repeat("x", 40)}
	if !d.ProgrammingMode() {
		t.Error("programming mode bit not reported")
	}
	if d.SerialString() != "00C5:01020304" {
		t.Errorf("SerialString = %q", d.SerialString())
	}
	b := d.AppendTo(nil)
	if len(b) != DeviceInfoLen {
		t.Fatalf("encoded %d octets", len(b))
	}
	got, _, err := ParseDIB(b)
	if err != nil {
		t.Fatal(err)
	}
	di := got.(DeviceInfo)
	// Latin-1 is kept, the snowman becomes '?', and the name is cut at 30
	// octets.
	if want := string([]rune("Bürø ? " + strings.Repeat("x", 40))[:30]); di.Name != want {
		t.Errorf("Name = %q, want %q", di.Name, want)
	}
	if di.Multicast != netip.IPv4Unspecified() {
		t.Errorf("Multicast = %v, want 0.0.0.0 for an unset address", di.Multicast)
	}
	if (DeviceInfo{}).ProgrammingMode() {
		t.Error("programming mode reported for status 0")
	}
}

func TestDIBAccessors(t *testing.T) {
	m, err := Parse(mustHex(t, loadGoldenHex(t, "description_response")))
	if err != nil {
		t.Fatal(err)
	}
	ds := m.(*DescriptionResponse).DIBs
	if di, ok := ds.DeviceInfo(); !ok || di.Name != "KNX IP Router" || di.Address.String() != "1.1.1" {
		t.Errorf("DeviceInfo = %+v %v", di, ok)
	}
	sup, ok := ds.SupportedServices()
	if !ok || sup.Secured {
		t.Fatalf("SupportedServices = %+v %v", sup, ok)
	}
	if v, ok := sup.Version(FamilyTunnelling); !ok || v != 1 {
		t.Errorf("tunnelling version %d %v", v, ok)
	}
	if _, ok := sup.Version(FamilySecurity); ok {
		t.Error("security family reported in supported services")
	}
	sec, ok := ds.SecuredServices()
	if !ok || !sec.Secured || sec.Type() != DIBSecuredServices {
		t.Errorf("SecuredServices = %+v %v", sec, ok)
	}
	if d, ok := ds.Find(DIBManufacturerData); !ok || d.(ManufacturerData).Manufacturer != 0x00fa {
		t.Errorf("Find(MFR_DATA) = %v %v", d, ok)
	}
	if _, ok := ds.Find(DIBTunnellingInfo); ok {
		t.Error("Find found an absent block")
	}
	var empty DIBs
	if _, ok := empty.DeviceInfo(); ok {
		t.Error("DeviceInfo in empty DIBs")
	}
	if _, ok := empty.SupportedServices(); ok {
		t.Error("SupportedServices in empty DIBs")
	}
	if _, ok := empty.SecuredServices(); ok {
		t.Error("SecuredServices in empty DIBs")
	}
	// The types of every DIB.
	for _, c := range []struct {
		d DIB
		t DIBType
	}{
		{DeviceInfo{}, DIBDeviceInfo}, {ServiceFamilies{}, DIBSupportedServices}, {IPConfig{}, DIBIPConfig},
		{IPCurrentConfig{}, DIBIPCurrentConfig}, {KNXAddresses{}, DIBKNXAddresses}, {TunnellingInfo{}, DIBTunnellingInfo},
		{ExtendedDeviceInfo{}, DIBExtendedDeviceInfo}, {ManufacturerData{}, DIBManufacturerData}, {UnknownDIB{DIBType: 0x42}, 0x42},
	} {
		if c.d.Type() != c.t {
			t.Errorf("%T.Type() = %v", c.d, c.d.Type())
		}
		if b := c.d.AppendTo(nil); int(b[0]) != len(b) || DIBType(b[1]) != c.t {
			t.Errorf("%T encodes % X", c.d, b)
		}
	}
	if !(TunnelSlot{Status: 0x05}).Free() || (TunnelSlot{Status: 0x06}).Free() {
		t.Error("TunnelSlot.Free")
	}
	// Zero-valued addresses encode as 0.0.0.0.
	if b := (IPConfig{}).AppendTo(nil); !bytes.Equal(b[2:14], make([]byte, 12)) {
		t.Errorf("zero IPConfig % X", b)
	}
}

func loadGoldenHex(tb testing.TB, name string) string {
	for _, g := range loadGolden(tb) {
		if g.Name == name {
			return g.Hex
		}
	}
	tb.Fatalf("no golden frame %s", name)
	return ""
}

// TestRoundTripConstructed encodes messages built in code (not from golden
// octets) and decodes them back.
func TestRoundTripConstructed(t *testing.T) {
	msgs := []Message{
		&SearchRequestExt{Discovery: udp("10.0.0.1:1234")},
		&SearchResponse{Control: udp("10.0.0.2:3671")},
		&DescriptionResponse{DIBs: DIBs{TunnellingInfo{MaxAPDU: 248}}},
		&ConnectRequest{Control: TCPHPAI(), Data: TCPHPAI(), CRI: TunnelCRI(TunnelRaw)},
		&ConnectResponse{Channel: 1, Status: StatusNoMoreUniqueConns},
		&TunnellingFeature{Type: TunnellingFeatureResponseType, Channel: 1, Seq: 255, Feature: FeatureIndividualAddress, ReturnCode: 0x01, Value: []byte{0x11, 0x05}},
		&RoutingBusy{DeviceState: 1, WaitTime: 0xFFFF, Control: 0x1234},
		&RoutingLostMessage{DeviceState: 2, Lost: 0xFFFF},
		&DeviceConfigurationAck{Channel: 9, Seq: 9, Status: StatusDataConnection},
		&SecureWrapper{SessionID: 0xFFFF, Encrypted: make([]byte, HeaderLen)},
		&SessionStatus{Status: SessionClose},
	}
	for _, m := range msgs {
		b, err := Marshal(m)
		if err != nil {
			t.Fatalf("%s: %v", m.Service(), err)
		}
		back, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: Parse: %v", m.Service(), err)
		}
		again, _ := Marshal(back)
		if !bytes.Equal(again, b) {
			t.Fatalf("%s: % X then % X", m.Service(), b, again)
		}
		if back.Service() != m.Service() {
			t.Fatalf("service %s, want %s", back.Service(), m.Service())
		}
	}
}
