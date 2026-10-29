// SPDX-License-Identifier: MIT

package knxnetip

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/otfabric/go-knx"
)

type goldenFrame struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	Hex     string `json:"hex"`
}

// loadGolden reads testdata/frames.json (see its _note for provenance).
func loadGolden(tb testing.TB) []goldenFrame {
	tb.Helper()
	raw, err := os.ReadFile("testdata/frames.json")
	if err != nil {
		tb.Fatal(err)
	}
	var f struct {
		Frames []goldenFrame `json:"frames"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		tb.Fatal(err)
	}
	return f.Frames
}

func mustHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func udp(s string) HPAI { return HPAI{Protocol: IPv4UDP, Addr: ap(s)} }

var (
	testMAC16 = [16]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}
	testKey32 = func() (k [32]byte) {
		for i := range k {
			k[i] = byte(i)
		}
		return
	}()
	testDeviceInfo = DeviceInfo{
		Medium: MediumTP1, Status: 0, Address: knx.MustParseIndividualAddress("1.1.1"),
		Serial: [6]byte{0x00, 0xfa, 0x12, 0x34, 0x56, 0x78}, Multicast: netip.MustParseAddr("224.0.23.12"),
		MAC: [6]byte{0x00, 0x24, 0x6d, 0x01, 0x02, 0x03}, Name: "KNX IP Router",
	}
	testFamilies = ServiceFamilies{Families: []ServiceFamily{{FamilyCore, 1}, {FamilyDeviceManagement, 1}, {FamilyTunnelling, 1}, {FamilyRouting, 1}}}
)

// goldenWant is the decoded form of every frame of testdata/frames.json.
var goldenWant = map[string]Message{
	"search_request":            &SearchRequest{Discovery: udp("224.0.23.12:3671")},
	"search_request_route_back": &SearchRequest{Discovery: udp("0.0.0.0:0")},
	"search_request_ext": &SearchRequestExt{Discovery: udp("192.168.1.2:50001"), Params: []SearchParam{
		{Type: SRPProgrammingMode, Mandatory: true},
		{Type: SRPRequestDIBs, Data: []byte{1, 2}},
		{Type: SRPMACAddress, Data: []byte{0x00, 0x24, 0x6d, 0x01, 0x02, 0x03}},
	}},
	"search_response": &SearchResponse{Control: udp("192.168.1.100:3671"), DIBs: DIBs{testDeviceInfo, testFamilies}},
	"search_response_ext": &SearchResponse{Extended: true, Control: udp("192.168.1.100:3671"), DIBs: DIBs{
		testDeviceInfo, testFamilies,
		TunnellingInfo{MaxAPDU: 254, Slots: []TunnelSlot{{Address: 0x1101, Status: 5}, {Address: 0x1102, Status: 6}}},
		ExtendedDeviceInfo{MediumStatus: 1, MaxAPDU: 254, DeviceDescriptor: 0x091a},
		UnknownDIB{DIBType: 0x99, Data: []byte{0xab, 0xcd}},
	}},
	"description_request": &DescriptionRequest{Control: udp("192.168.1.2:50001")},
	"description_response": &DescriptionResponse{DIBs: DIBs{
		testDeviceInfo, testFamilies,
		IPConfig{IP: netip.MustParseAddr("192.168.1.100"), Mask: netip.MustParseAddr("255.255.255.0"), Gateway: netip.MustParseAddr("192.168.1.1"), Capabilities: 3, Assignment: 2},
		IPCurrentConfig{IP: netip.MustParseAddr("192.168.1.100"), Mask: netip.MustParseAddr("255.255.255.0"), Gateway: netip.MustParseAddr("192.168.1.1"), DHCPServer: netip.MustParseAddr("192.168.1.1"), Assignment: 4},
		KNXAddresses{Addresses: []knx.IndividualAddress{0x1101, 0x1102}},
		ServiceFamilies{Secured: true, Families: []ServiceFamily{{FamilyTunnelling, 1}}},
		ManufacturerData{Manufacturer: 0x00fa, Data: []byte{1, 2, 3, 4}},
	}},
	"connect_request_tunnel": &ConnectRequest{Control: udp("192.168.1.2:50001"), Data: udp("192.168.1.2:50002"), CRI: TunnelCRI(TunnelLinkLayer)},
	"connect_request_tunnel_ext_cri": &ConnectRequest{Control: udp("192.168.1.2:50001"), Data: udp("192.168.1.2:50002"),
		CRI: CRI{Type: TunnelConnection, Layer: TunnelLinkLayer, HasAddress: true, Address: 0x1105}},
	"connect_request_route_back_busmon":    &ConnectRequest{Control: RouteBackHPAI(), Data: RouteBackHPAI(), CRI: TunnelCRI(TunnelBusmonitor)},
	"connect_request_tcp":                  &ConnectRequest{Control: TCPHPAI(), Data: TCPHPAI(), CRI: TunnelCRI(TunnelLinkLayer)},
	"connect_request_device_mgmt":          &ConnectRequest{Control: udp("192.168.1.2:50001"), Data: udp("192.168.1.2:50002"), CRI: CRI{Type: DeviceManagementConnection}},
	"connect_request_remlog":               &ConnectRequest{Control: udp("192.168.1.2:50001"), Data: udp("192.168.1.2:50002"), CRI: CRI{Type: RemoteLoggingConnection, Data: []byte{0xaa, 0xbb}}},
	"connect_response_tunnel":              &ConnectResponse{Channel: 0x15, Data: udp("192.168.1.100:3671"), CRD: CRD{Type: TunnelConnection, Address: 0x11ff}},
	"connect_response_device_mgmt":         &ConnectResponse{Channel: 0x16, Data: udp("192.168.1.100:3671"), CRD: CRD{Type: DeviceManagementConnection}},
	"connect_response_remlog":              &ConnectResponse{Channel: 0x17, Data: udp("192.168.1.100:3671"), CRD: CRD{Type: RemoteLoggingConnection, Data: []byte{1}}},
	"connect_response_no_more_connections": &ConnectResponse{Status: StatusNoMoreConnections},
	"connect_response_refused_trailer":     &ConnectResponse{Status: StatusConnectionType, Trailer: []byte{1, 2}},
	"connectionstate_request":              &ConnectionStateRequest{Channel: 0x15, Control: udp("192.168.1.2:50001")},
	"connectionstate_response":             &ConnectionStateResponse{Channel: 0x15},
	"connectionstate_response_error":       &ConnectionStateResponse{Channel: 0x15, Status: StatusConnectionID},
	"disconnect_request":                   &DisconnectRequest{Channel: 0x15, Control: udp("192.168.1.2:50001")},
	"disconnect_response":                  &DisconnectResponse{Channel: 0x15},
	"tunnelling_request":                   &TunnellingRequest{Channel: 0x15, CEMI: []byte{0x11, 0x00, 0xbc, 0xe0, 0x00, 0x00, 0x0a, 0x03, 0x01, 0x00, 0x81}},
	"tunnelling_request_ind":               &TunnellingRequest{Channel: 0x15, Seq: 0x7f, CEMI: []byte{0x29, 0x00, 0xbc, 0xe0, 0x11, 0x05, 0x0a, 0x03, 0x03, 0x00, 0x80, 0x0c, 0x33}},
	"tunnelling_ack":                       &TunnellingAck{Channel: 0x15},
	"tunnelling_ack_error":                 &TunnellingAck{Channel: 0x15, Seq: 7, Status: StatusTunnellingLayer},
	"device_configuration_request":         &DeviceConfigurationRequest{Channel: 0x15, CEMI: []byte{0xfc, 0x00, 0x0b, 0x01, 0x35, 0x10, 0x01}},
	"device_configuration_ack":             &DeviceConfigurationAck{Channel: 0x15},
	"tunnelling_feature_get":               &TunnellingFeature{Type: TunnellingFeatureGetType, Channel: 0x15, Seq: 1, Feature: FeatureBusConnectionStatus},
	"tunnelling_feature_response":          &TunnellingFeature{Type: TunnellingFeatureResponseType, Channel: 0x15, Seq: 1, Feature: FeatureBusConnectionStatus, Value: []byte{1}},
	"tunnelling_feature_set":               &TunnellingFeature{Type: TunnellingFeatureSetType, Channel: 0x15, Seq: 2, Feature: FeatureInfoServiceEnable, Value: []byte{1}},
	"tunnelling_feature_info":              &TunnellingFeature{Type: TunnellingFeatureInfoType, Channel: 0x15, Seq: 3, Feature: FeatureBusConnectionStatus, Value: []byte{1}},
	"routing_indication":                   &RoutingIndication{CEMI: []byte{0x29, 0x00, 0xbc, 0xe0, 0x11, 0x01, 0x0a, 0x03, 0x01, 0x00, 0x81}},
	"routing_system_broadcast":             &RoutingIndication{SystemBroadcast: true, CEMI: []byte{0x29, 0x00, 0xac, 0xe0, 0x11, 0x01, 0x00, 0x00, 0x01, 0x03, 0xec}},
	"routing_lost_message":                 &RoutingLostMessage{Lost: 5},
	"routing_busy":                         &RoutingBusy{WaitTime: 100},
	"secure_wrapper": &SecureWrapper{SessionID: 1, Sequence: [6]byte{0, 0, 0, 0, 0, 1}, Serial: [6]byte{0x00, 0xfa, 0x12, 0x34, 0x56, 0x78},
		Encrypted: []byte{1, 2, 3, 4, 5, 6, 7, 8}, MAC: testMAC16},
	"session_request":       &SessionRequest{Control: udp("192.168.1.2:50001"), PublicKey: testKey32},
	"session_response":      &SessionResponse{SessionID: 1, PublicKey: testKey32, MAC: testMAC16},
	"session_authenticate":  &SessionAuthenticate{UserID: 1, MAC: testMAC16},
	"session_status":        &SessionStatus{Status: SessionUnauthenticated},
	"timer_notify":          &TimerNotify{Timer: [6]byte{0, 0, 0, 0, 1, 2}, Serial: [6]byte{0x00, 0xfa, 0x12, 0x34, 0x56, 0x78}, MAC: testMAC16},
	"unknown_service":       &Unknown{Type: 0x0601, Body: []byte{1, 2, 3}},
	"unknown_service_empty": &Unknown{Type: 0x7777},
}

// TestGoldenFrames decodes every golden frame to its expected message,
// encodes it back to the identical octets, and encodes the expected message
// to the same octets too.
func TestGoldenFrames(t *testing.T) {
	frames := loadGolden(t)
	if len(frames) != len(goldenWant) {
		t.Fatalf("%d golden frames, %d expectations", len(frames), len(goldenWant))
	}
	for _, g := range frames {
		t.Run(g.Name, func(t *testing.T) {
			want, ok := goldenWant[g.Name]
			if !ok {
				t.Fatalf("no expectation for %s", g.Name)
			}
			b := mustHex(t, g.Hex)
			m, err := Parse(b)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(m, want) {
				t.Fatalf("Parse:\n got %#v\nwant %#v", m, want)
			}
			if svc := ServiceType(binaryHex(t, g.Service)); m.Service() != svc {
				t.Fatalf("Service() = %s, want %s", m.Service(), svc)
			}
			out, err := Marshal(m)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !bytes.Equal(out, b) {
				t.Fatalf("decode→encode:\n got % X\nwant % X", out, b)
			}
			out2, err := Marshal(want)
			if err != nil || !bytes.Equal(out2, b) {
				t.Fatalf("encode expectation: % X, %v", out2, err)
			}
			// ReadFrame reads the same frame from a stream with trailing data.
			r := bytes.NewReader(append(append([]byte(nil), b...), 0x06, 0x10))
			got, err := ReadFrame(r)
			if err != nil || !bytes.Equal(got, b) {
				t.Fatalf("ReadFrame: % X, %v", got, err)
			}
		})
	}
}

func binaryHex(tb testing.TB, s string) uint16 {
	b := mustHex(tb, s[2:])
	return uint16(b[0])<<8 | uint16(b[1])
}
