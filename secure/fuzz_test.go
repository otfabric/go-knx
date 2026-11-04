// SPDX-License-Identifier: MIT

package secure

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-knx/knxnetip"
)

// fuzzKey is the session key of FuzzSessionFrames; the seeds are sealed with
// it, so the fuzzer starts from frames that authenticate.
var fuzzKey = Key{0x28, 0x9c, 0x1a, 0x07, 0x5b, 0x33, 0x50, 0x21, 0xe9, 0x10, 0x44, 0xd8, 0x6b, 0x7e, 0x00, 0x01}

func fuzzSeeds(f *testing.F) {
	f.Helper()
	serial := [6]byte{0x00, 0xfa, 0x12, 0x34, 0x56, 0x78}
	inner := []knxnetip.Message{
		&knxnetip.SessionAuthenticate{UserID: 2},
		&knxnetip.SessionStatus{Status: knxnetip.SessionKeepAlive},
		&knxnetip.ConnectionStateRequest{Channel: 1, Control: knxnetip.TCPHPAI()},
		&knxnetip.TunnellingRequest{Channel: 1, Seq: 0, CEMI: []byte{0x11, 0x00, 0xbc, 0xe0, 0x11, 0x0a, 0x0a, 0x03, 0x01, 0x00, 0x81}},
	}
	for i, m := range inner {
		b, err := knxnetip.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		w, err := Seal(fuzzKey, 7, uint64(i), serial, 0, b)
		if err != nil {
			f.Fatal(err)
		}
		raw, err := knxnetip.Marshal(w)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	for _, m := range []knxnetip.Message{
		&knxnetip.SessionRequest{Control: knxnetip.TCPHPAI(), PublicKey: [32]byte{9}},
		&knxnetip.SessionResponse{SessionID: 7, PublicKey: [32]byte{1}},
		&knxnetip.SessionAuthenticate{UserID: 1},
		&knxnetip.SessionStatus{Status: knxnetip.SessionClose},
		NewTimerNotify(fuzzKey, 1234, serial, 0x77),
	} {
		raw, err := knxnetip.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
}

// FuzzSessionFrames feeds arbitrary octets through the decoding and
// verification of the KNX IP Secure frames: SECURE_WRAPPER (Open and a
// session's Unwrap with its replay check), SESSION_REQUEST and
// SESSION_RESPONSE (key agreement with an arbitrary public key, MAC
// verification), SESSION_AUTHENTICATE and TIMER_NOTIFY. Nothing may panic;
// a wrapper that opens must be the one Seal produces for the frame it
// carries (no forgery), and the same wrapper must not open twice in a
// session (no replay).
func FuzzSessionFrames(f *testing.F) {
	fuzzSeeds(f)
	kp, err := NewKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := knxnetip.Parse(b)
		if err != nil {
			return
		}
		switch m := m.(type) {
		case *knxnetip.SecureWrapper:
			frame, err := Open(fuzzKey, m)
			if err != nil {
				if frame != nil {
					t.Fatalf("frame % X with error %v", frame, err)
				}
			} else {
				again, err := Seal(fuzzKey, m.SessionID, Uint48(m.Sequence), m.Serial, m.MessageTag, frame)
				if err != nil {
					t.Fatalf("an opened frame does not seal again: %v", err)
				}
				if again.MAC != m.MAC || !bytes.Equal(again.Encrypted, m.Encrypted) {
					t.Fatalf("opened a wrapper Seal does not produce: % X", b)
				}
				if h, err := knxnetip.ParseHeader(frame); err != nil || h.Service == knxnetip.SecureWrapperType {
					t.Fatalf("opened frame % X: %v", frame, err)
				}
			}
			s := NewSession(m.SessionID, fuzzKey, [6]byte{})
			if _, err := s.Unwrap(m); err == nil {
				if _, err := s.Unwrap(m); err == nil {
					t.Fatal("the same wrapper opened twice in a session")
				}
			}
			// Another key never opens it.
			other := fuzzKey
			other[0] ^= 0xff
			if _, err := Open(other, m); err == nil {
				t.Fatalf("a wrapper opened under two keys: % X", b)
			}
		case *knxnetip.SessionRequest:
			if k, err := kp.SessionKey(m.PublicKey); err == nil && k == (Key{}) {
				t.Fatal("zero session key")
			}
			_ = ResponseMAC(fuzzKey, 1, m.PublicKey, kp.Public)
		case *knxnetip.SessionResponse:
			if _, err := kp.SessionKey(m.PublicKey); err == nil {
				want := ResponseMAC(fuzzKey, m.SessionID, kp.Public, m.PublicKey)
				if Equal(want, m.MAC) && m.MAC == ([16]byte{}) {
					t.Fatal("zero MAC accepted")
				}
			}
		case *knxnetip.SessionAuthenticate:
			_ = Equal(m.MAC, AuthenticateMAC(fuzzKey, m.UserID, kp.Public, kp.Public))
		case *knxnetip.TimerNotify:
			if err := VerifyTimerNotify(fuzzKey, m); err == nil {
				want := NewTimerNotify(fuzzKey, Uint48(m.Timer), m.Serial, m.MessageTag)
				if want.MAC != m.MAC {
					t.Fatalf("TIMER_NOTIFY verified with a MAC NewTimerNotify does not produce: % X", b)
				}
			}
		}
	})
}
