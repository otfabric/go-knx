// SPDX-License-Identifier: MIT

package secure

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/knxnetip"
)

// The vectors are the AN159 v06 example frames and the handshake of
// xknx's secure session tests (MIT), see docs/standards/SPECIFICATIONS.md.

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func key(t *testing.T, s string) (k Key) {
	copy(k[:], unhex(t, s))
	return k
}

func arr16(t *testing.T, s string) (a [16]byte) {
	copy(a[:], unhex(t, s))
	return a
}

func arr32(t *testing.T, s string) (a [32]byte) {
	copy(a[:], unhex(t, s))
	return a
}

func arr6(t *testing.T, s string) (a [6]byte) {
	copy(a[:], unhex(t, s))
	return a
}

func TestPasswordKeys(t *testing.T) {
	d, err := DeviceAuthenticationCode("trustme")
	if err != nil || d != key(t, "e1 58 e4 01 20 47 bd 6c c4 1a af bc 5c 04 c1 fc") {
		t.Errorf("device authentication code %x, %v", d, err)
	}
	u, err := UserPasswordKey("secret")
	if err != nil || u != key(t, "03 fc ed b6 66 60 25 1e c8 1a 1a 71 69 01 69 6a") {
		t.Errorf("user password key %x, %v", u, err)
	}
	if _, err := UserPasswordKey("€"); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("non Latin-1 password: %v", err)
	}
}

// AN159 example: a ROUTING_INDICATION in a SECURE_WRAPPER.
func TestSealRouting(t *testing.T) {
	k := key(t, "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f")
	frame := unhex(t, "06 10 05 30 00 11 29 00 bc d0 11 59 0a de 01 00 81")
	w, err := Seal(k, 0, 0xc0c1c2c3c4c5, arr6(t, "00 fa 12 34 56 78"), 0xaffe, frame)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(w.Encrypted) != "b7ee7e8a1c2f7bbabec775fd6e10d0bc4b" {
		t.Errorf("encrypted %x", w.Encrypted)
	}
	if w.MAC != arr16(t, "72 12 a0 3a aa e4 9d a8 56 89 77 4c 1d 2b 4d a4") {
		t.Errorf("MAC %x", w.MAC)
	}
	got, err := Open(k, w)
	if err != nil || string(got) != string(frame) {
		t.Fatalf("open: %x, %v", got, err)
	}
	w.Encrypted[0] ^= 1
	if _, err := Open(k, w); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tampered frame: %v", err)
	}
	if _, err := Seal(k, 0, MaxSequence+1, [6]byte{}, 0, frame); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("sequence overflow: %v", err)
	}
	if _, err := Seal(k, 0, 0, [6]byte{}, 0, make([]byte, knxnetip.MaxFrameLen)); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("long frame: %v", err)
	}
}

func TestOpenNested(t *testing.T) {
	var k Key
	inner, _ := Seal(k, 1, 0, [6]byte{}, 0, unhex(t, "06 10 02 07 00 08 01 00"))
	b, _ := knxnetip.Marshal(inner)
	w, _ := Seal(k, 1, 1, [6]byte{}, 0, b)
	if _, err := Open(k, w); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("nested wrapper: %v", err)
	}
	w, _ = Seal(k, 1, 1, [6]byte{}, 0, []byte{1, 2})
	if _, err := Open(k, w); !errors.Is(err, knx.ErrMalformed) {
		t.Errorf("short inner frame: %v", err)
	}
}

// The handshake of xknx's session test: client key pair, server public
// key, device password "trustme", user 1 with password "secret".
func TestHandshake(t *testing.T) {
	priv, err := ecdh.X25519().NewPrivateKey(unhex(t, "b8 fa bd 62 66 5d 8b 9e 8a 9d 8b 1f 4b ca 42 c8 c2 78 9a 61 10 f5 0e 9d d7 85 b3 ed e8 83 f3 78"))
	if err != nil {
		t.Fatal(err)
	}
	kp := &KeyPair{priv: priv}
	copy(kp.Public[:], priv.PublicKey().Bytes())
	client := arr32(t, "0a a2 27 b4 fd 7a 32 31 9b a9 96 0a c0 36 ce 0e 5c 45 07 b5 ae 55 16 1f 10 78 b1 dc fb 3c b6 31")
	server := arr32(t, "bd f0 99 90 99 23 14 3e f0 a5 de 0b 3b e3 68 7b c5 bd 3c f5 f9 e6 f9 01 69 9c d8 70 ec 1f f8 24")
	if kp.Public != client {
		t.Fatalf("public key %x", kp.Public)
	}
	dev, _ := DeviceAuthenticationCode("trustme")
	if got := ResponseMAC(dev, 1, client, server); !Equal(got, arr16(t, "a9 22 50 5a aa 43 61 63 57 0b d5 49 4c 2d f2 a3")) {
		t.Errorf("response MAC %x", got)
	}
	user, _ := UserPasswordKey("secret")
	if got := AuthenticateMAC(user, 1, client, server); got != arr16(t, "1f 1d 59 ea 9f 12 a1 52 e5 d9 72 7f 08 46 2c de") {
		t.Errorf("authenticate MAC %x", got)
	}
	sk, err := kp.SessionKey(server)
	if err != nil {
		t.Fatal(err)
	}
	// The wrapped SESSION_AUTHENTICATE (message tag af fe in the test).
	auth, _ := knxnetip.Marshal(&knxnetip.SessionAuthenticate{UserID: 1, MAC: AuthenticateMAC(user, 1, client, server)})
	w, err := Seal(sk, 1, 0, arr6(t, "00 fa 12 34 56 78"), 0xaffe, auth)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(w.Encrypted) != "7915a4f36e6e4208d28b4a207d8f35c0d138c26a7b5e7169" || w.MAC != arr16(t, "52 db a8 e7 e4 bd 80 bd 7d 86 8a 3a e7 87 49 de") {
		t.Errorf("wrapped authenticate %x %x", w.Encrypted, w.MAC)
	}
	// The server's SESSION_STATUS (authentication success).
	status := &knxnetip.SecureWrapper{SessionID: 1, Serial: arr6(t, "00 fa aa aa aa aa"), MessageTag: 0xaffe,
		Encrypted: unhex(t, "26 15 6d b5 c7 49 88 8f"), MAC: arr16(t, "a3 73 c3 e0 b4 bd e4 49 7c 39 5e 4b 1c 2f 46 a1")}
	s := NewSession(1, sk, [6]byte{})
	frame, err := s.Unwrap(status)
	if err != nil {
		t.Fatal(err)
	}
	m, err := knxnetip.Parse(frame)
	if st, ok := m.(*knxnetip.SessionStatus); err != nil || !ok || st.Status != knxnetip.SessionAuthSuccess {
		t.Errorf("session status %v, %v", m, err)
	}
	if _, err := s.Unwrap(status); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("replay: %v", err)
	}
	if _, err := kp.SessionKey([32]byte{}); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("low order public key: %v", err)
	}
}

func TestSessionRoundTrip(t *testing.T) {
	a, _ := NewKeyPair()
	b, _ := NewKeyPair()
	ka, _ := a.SessionKey(b.Public)
	kb, _ := b.SessionKey(a.Public)
	if ka != kb {
		t.Fatal("session keys differ")
	}
	tx, rx := NewSession(7, ka, [6]byte{1}), NewSession(7, kb, [6]byte{2})
	for i := 0; i < 3; i++ {
		raw, err := tx.Marshal(&knxnetip.SessionStatus{Status: knxnetip.SessionKeepAlive})
		if err != nil {
			t.Fatal(err)
		}
		m, err := knxnetip.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		w := m.(*knxnetip.SecureWrapper)
		if Uint48(w.Sequence) != uint64(i) {
			t.Errorf("sequence %d, want %d", Uint48(w.Sequence), i)
		}
		if _, err := rx.Unwrap(w); err != nil {
			t.Fatal(err)
		}
	}
	w, _ := tx.Wrap([]byte{6, 0x10, 2, 9, 0, 6})
	w.SessionID = 8
	if _, err := rx.Unwrap(w); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("other session: %v", err)
	}
	tx.tx = MaxSequence + 1
	if _, err := tx.Wrap(nil); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("exhausted: %v", err)
	}
}

// The MAC was computed with xknx 4.0.0's primitives (the TIMER_NOTIFY
// vector of xknx's tests uses a 32-octet key).
func TestTimerNotify(t *testing.T) {
	k := key(t, "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f")
	m := NewTimerNotify(k, 0x123456789abc, arr6(t, "00 fa 12 34 56 78"), 0x1234)
	if m.MAC != arr16(t, "d3 1c b3 88 91 0a fc e7 33 fc 05 e1 57 b8 a7 6e") {
		t.Errorf("MAC %x", m.MAC)
	}
	if err := VerifyTimerNotify(k, m); err != nil {
		t.Error(err)
	}
	m.Timer[5]++
	if err := VerifyTimerNotify(k, m); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tampered timer: %v", err)
	}
}
