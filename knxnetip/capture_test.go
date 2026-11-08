// SPDX-License-Identifier: MIT

package knxnetip_test

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"testing"

	"github.com/otfabric/go-knx/internal/capture"
	"github.com/otfabric/go-knx/knxnetip"
)

// knxnetipCaptures are the committed KNXnet/IP captures.
func knxnetipCaptures(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{"wireshark", "wireshark-14825"} {
		m, err := filepath.Glob(filepath.Join(capture.Dir(), dir, "*"))
		if err != nil || len(m) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, p := range m {
			out = append(out, filepath.Join(dir, filepath.Base(p)))
		}
	}
	return out
}

// TestCaptureFrames decodes every KNXnet/IP frame of the recorded and the
// Wireshark test captures and encodes it again to the recorded octets;
// frames carried over TCP are read with ReadFrame from the reassembled
// stream as well. The frames go-knx refuses are counted per capture, and
// each is a frame Wireshark marks malformed too or a classified
// difference (testdata/captures/README.md).
func TestCaptureFrames(t *testing.T) {
	refused := map[string]int{
		"wireshark/wireshark-test_synthetic_knxip-decrypt-coverage.pcap.gz": 7, // wrappers of 0 to 5 octets
		"wireshark-14825/test-tool_abb-ipr-s_01-core.txt":                   15,
		"wireshark-14825/test-tool_abb-ipr-s_03-tunneling.txt":              1,
		"wireshark-14825/test-tool_abb-ipr-s_05-remotediagandconfig.txt":    5,
		"wireshark-14825/test-tool_abb-ipr-s_07-security.txt":               5,
	}
	total, decoded := 0, 0
	for _, rel := range knxnetipCaptures(t) {
		f, err := capture.Load(rel)
		if err != nil {
			t.Fatal(err)
		}
		bad := 0
		var stream bytes.Buffer
		for _, d := range f.IP {
			frames, rest := capture.Frames(d.Data)
			if len(frames) == 0 || len(rest) > 0 {
				frames = [][]byte{d.Data}
			}
			for _, b := range frames {
				total++
				m, err := knxnetip.Parse(b)
				if err != nil {
					bad++
					continue
				}
				decoded++
				out, err := knxnetip.Marshal(m)
				if err != nil || !bytes.Equal(out, b) {
					t.Fatalf("%s frame %d: %T encodes to % X (%v), recorded % X", rel, d.Frame, m, out, err, b)
				}
				if d.Transport == capture.TCP {
					stream.Write(b)
				}
			}
		}
		for stream.Len() > 0 {
			b, err := knxnetip.ReadFrame(&stream)
			if err != nil {
				t.Fatalf("%s: ReadFrame: %v", rel, err)
			}
			if _, err := knxnetip.Parse(b); err != nil {
				t.Fatalf("%s: % X: %v", rel, b, err)
			}
		}
		if bad != refused[rel] {
			t.Errorf("%s: %d frames refused, want %d", rel, bad, refused[rel])
		}
	}
	t.Logf("%d KNXnet/IP frames, %d decoded and re-encoded byte for byte", total, decoded)
}

// TestCaptureDeviceIdentity: the devices' DEVICE_INFO blocks in the
// description and search responses of the live recordings decode to the
// identities Wireshark 4.6.9 shows (name, MAC, serial number, routing
// multicast address). The ABB IP-Router IPR/S's extended search
// responses only decode since go-knx keeps its malformed optional blocks.
func TestCaptureDeviceIdentity(t *testing.T) {
	wireshark := []string{
		"ABB IP-Router IPR/S|00:0c:de:02:80:8e|0002:81FDFF50|224.0.23.12",
		"ABB IP-Router IPR/S|00:0c:de:02:80:8e|0002:81FDFF50|225.0.23.12",
		"ABB IP-Router IPR/S|00:0c:de:02:80:8e|0002:81FDFF50|226.0.23.12",
		"ABB IPS/S2.1|00:0c:de:9e:50:54|0002:549EFF50|0.0.0.0",
	}
	seen := map[string]int{}
	extended := 0
	for _, rel := range knxnetipCaptures(t) {
		if filepath.Dir(rel) != "wireshark-14825" {
			continue
		}
		f, err := capture.Load(rel)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.IP {
			frames, _ := capture.Frames(d.Data)
			for _, b := range frames {
				m, err := knxnetip.Parse(b)
				if err != nil {
					continue
				}
				var dibs knxnetip.DIBs
				switch m := m.(type) {
				case *knxnetip.SearchResponse:
					dibs = m.DIBs
					if m.Extended {
						extended++
					}
				case *knxnetip.DescriptionResponse:
					dibs = m.DIBs
				default:
					continue
				}
				di, ok := dibs.DeviceInfo()
				if !ok {
					continue
				}
				seen[fmt.Sprintf("%s|%s|%s|%s", di.Name, net.HardwareAddr(di.MAC[:]), di.SerialString(), di.Multicast)]++
			}
		}
	}
	got := slices.Sorted(func(yield func(string) bool) {
		for k := range seen {
			if !yield(k) {
				return
			}
		}
	})
	if !slices.Equal(got, wireshark) {
		t.Fatalf("identities\n got %q\nwant %q", got, wireshark)
	}
	if extended != 91 {
		t.Errorf("%d extended search responses decoded, want 91", extended)
	}
	t.Logf("device identities %v", seen)
}
