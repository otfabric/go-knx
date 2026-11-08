// SPDX-License-Identifier: MIT

package secure_test

import (
	"errors"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/capture"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/secure"
)

// wiresharkTestKey is the key Wireshark's test suite publishes for its
// KNX IP Secure captures (kip.key_1 in test/suite_decryption.py).
var wiresharkTestKey = secure.Key{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

func messages(t *testing.T, rel string) []knxnetip.Message {
	t.Helper()
	f, err := capture.Load(rel)
	if err != nil {
		t.Fatal(err)
	}
	var out []knxnetip.Message
	for _, d := range f.IP {
		frames, _ := capture.Frames(d.Data)
		for _, b := range frames {
			if m, err := knxnetip.Parse(b); err == nil {
				out = append(out, m)
			}
		}
	}
	return out
}

// TestCaptureSecureWrapper opens the SECURE_WRAPPER of Wireshark's test
// capture with the published test key: it carries a ROUTING_INDICATION
// with an L_Data.ind 0.0.0 -> 2.2.0 A_DeviceDescriptor_Read, as
// Wireshark decrypts it. Another key fails the MAC check.
func TestCaptureSecureWrapper(t *testing.T) {
	ms := messages(t, "wireshark/wireshark-test_synthetic_knxip-securewrapper.pcap")
	if len(ms) != 1 {
		t.Fatalf("%d messages", len(ms))
	}
	w := ms[0].(*knxnetip.SecureWrapper)
	frame, err := secure.Open(wiresharkTestKey, w)
	if err != nil {
		t.Fatal(err)
	}
	m, err := knxnetip.Parse(frame)
	if err != nil {
		t.Fatal(err)
	}
	ri, ok := m.(*knxnetip.RoutingIndication)
	if !ok {
		t.Fatalf("%T", m)
	}
	c, err := cemi.Parse(ri.CEMI)
	if err != nil {
		t.Fatal(err)
	}
	ld := c.(*cemi.LData)
	p, err := apdu.Parse(ld.TPDU)
	if err != nil || ld.MsgCode != cemi.LDataInd || ld.Source.String() != "0.0.0" || ld.DestinationString() != "2.2.0" ||
		p.APCI != apdu.DeviceDescriptorReadService {
		t.Fatalf("%s %+v %v", ld, p, err)
	}
	bad := wiresharkTestKey
	bad[0] ^= 1
	if _, err := secure.Open(bad, w); !errors.Is(err, knx.ErrSecurity) {
		t.Fatalf("other key: %v", err)
	}
}

// TestCaptureTimerNotify verifies the TIMER_NOTIFY of Wireshark's test
// capture with the published test key (Wireshark reports "OK").
func TestCaptureTimerNotify(t *testing.T) {
	ms := messages(t, "wireshark/wireshark-test_synthetic_knxip-timernotify.pcap")
	if len(ms) != 1 {
		t.Fatalf("%d messages", len(ms))
	}
	m := ms[0].(*knxnetip.TimerNotify)
	if err := secure.VerifyTimerNotify(wiresharkTestKey, m); err != nil {
		t.Fatal(err)
	}
	bad := wiresharkTestKey
	bad[15] ^= 1
	if err := secure.VerifyTimerNotify(bad, m); err == nil {
		t.Fatal("other key verified")
	}
}

// TestCaptureSecurePlaceholders: Wireshark's decrypt coverage capture
// holds wrappers and timer notifications with made-up MACs; with its two
// test keys every one fails authentication in go-knx too, as in
// Wireshark, and nothing panics.
func TestCaptureSecurePlaceholders(t *testing.T) {
	keys := []secure.Key{wiresharkTestKey, {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}}
	wrappers, timers := 0, 0
	for _, m := range messages(t, "wireshark/wireshark-test_synthetic_knxip-decrypt-coverage.pcap.gz") {
		for _, k := range keys {
			switch m := m.(type) {
			case *knxnetip.SecureWrapper:
				if _, err := secure.Open(k, m); err == nil {
					t.Fatalf("wrapper %+v opened", m)
				}
			case *knxnetip.TimerNotify:
				if secure.VerifyTimerNotify(k, m) == nil {
					t.Fatalf("timer notify %+v verified", m)
				}
			}
		}
		switch m.(type) {
		case *knxnetip.SecureWrapper:
			wrappers++
		case *knxnetip.TimerNotify:
			timers++
		}
	}
	// 36 wrappers in the capture; the 7 of 0 to 5 octets carry no
	// KNXnet/IP header and go-knx refuses them at decode.
	if wrappers != 29 || timers != 6 {
		t.Fatalf("%d wrappers, %d timer notifications", wrappers, timers)
	}
}
