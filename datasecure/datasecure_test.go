// SPDX-License-Identifier: MIT

package datasecure

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
)

// The vectors are those of xknx's Data Secure tests (MIT) with the group
// key of 0/4/0 from its SecureTest keyring.

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T, s string) *cemi.LData {
	t.Helper()
	f, err := cemi.Parse(unhex(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return f.(*cemi.LData)
}

func marshal(t *testing.T, f *cemi.LData) string {
	t.Helper()
	b, err := cemi.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

var key040 = Key{0xdf, 0xdf, 0x23, 0xa5, 0x9f, 0xbb, 0x40, 0x40, 0x40, 0x91, 0xd1, 0xc1, 0x62, 0x08, 0x7e, 0x8b}

func group(t *testing.T, s string) knx.GroupAddress {
	g, err := knx.ParseGroupAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSealVectors(t *testing.T) {
	src, _ := knx.ParseIndividualAddress("5.0.1")
	read := cemi.NewGroupFrame(cemi.LDataReq, src, group(t, "0/4/0"), knx.PriorityLow, apdu.GroupValueRead())
	s, err := Seal(key040, read, 160170101607, GroupData)
	if err != nil {
		t.Fatal(err)
	}
	if got := marshal(t, s); got != "1100bce0500104000e03f11000254ae1cb67cd184afe5744" {
		t.Errorf("secured read %s", got)
	}
	write, _ := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{255, 0, 5}})
	w := cemi.NewGroupFrame(cemi.LDataReq, src, group(t, "0/4/0"), knx.PriorityLow, write)
	s, err = Seal(key040, w, 160170101607, GroupData)
	if err != nil {
		t.Fatal(err)
	}
	if got := marshal(t, s); got != "11003ce0500104001103f11000254ae1cb67cd98e577b519be47bb" {
		t.Errorf("secured extended write %s", got)
	}
	plain, seq, scf, err := Open(key040, s)
	if err != nil || seq != 160170101607 || scf != GroupData {
		t.Fatalf("open: %v %d %+v", err, seq, scf)
	}
	if got := marshal(t, plain); got != marshal(t, w) {
		t.Errorf("round trip %s, want %s", got, marshal(t, w))
	}
}

func TestOpenVector(t *testing.T) {
	// 4.0.9 -> 0/4/0 GroupValueResponse (116, 41, 41), sequence 155806854986.
	f := parse(t, "29003ce0400904001103f110002446cfef4ac085e7092ab062b44d")
	plain, seq, _, err := Open(key040, f)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 155806854986 {
		t.Errorf("sequence %d", seq)
	}
	if got := marshal(t, plain); got != "2900bce040090400040040742929" {
		t.Errorf("plain %s", got)
	}
	f.TPDU[10] ^= 1
	if _, _, _, err := Open(key040, f); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tampered: %v", err)
	}
}

func TestSCF(t *testing.T) {
	for _, b := range []byte{0x00, 0x10, 0x90, 0x18, 0x12, 0x13} {
		if got := ParseSCF(b).Byte(); got != b {
			t.Errorf("%02x -> %02x", b, got)
		}
	}
	if GroupData.Byte() != 0x10 {
		t.Errorf("group data SCF %02x", GroupData.Byte())
	}
}

func TestAuthOnly(t *testing.T) {
	src, _ := knx.ParseIndividualAddress("1.1.1")
	w, _ := apdu.GroupValueWrite(apdu.GroupValue{Small: true, Data: []byte{1}})
	f := cemi.NewGroupFrame(cemi.LDataInd, src, group(t, "1/2/3"), knx.PriorityLow, w)
	scf := SCF{Algorithm: AuthOnly}
	s, err := Seal(key040, f, 42, scf)
	if err != nil {
		t.Fatal(err)
	}
	if string(s.TPDU[9:11]) != string([]byte{0x00, 0x81}) {
		t.Errorf("authenticated APDU is not plain: %x", s.TPDU)
	}
	plain, seq, got, err := Open(key040, s)
	if err != nil || seq != 42 || got != scf || marshal(t, plain) != marshal(t, f) {
		t.Fatalf("open: %v %d %+v", err, seq, got)
	}
	s.TPDU[10] ^= 1
	if _, _, _, err := Open(key040, s); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tampered: %v", err)
	}
}

func TestSealOpenErrors(t *testing.T) {
	src, _ := knx.ParseIndividualAddress("1.1.1")
	f := cemi.NewGroupFrame(cemi.LDataInd, src, group(t, "1/2/3"), knx.PriorityLow, apdu.GroupValueRead())
	if _, err := Seal(key040, f, MaxSequence+1, GroupData); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("sequence: %v", err)
	}
	short := f.Clone()
	short.TPDU = []byte{0}
	if _, err := Seal(key040, short, 1, GroupData); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("short TPDU: %v", err)
	}
	long := f.Clone()
	long.TPDU = make([]byte, 250)
	if _, err := Seal(key040, long, 1, GroupData); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("long TPDU: %v", err)
	}
	if _, err := Seal(key040, f, 1, SCF{Algorithm: 5}); !errors.Is(err, knx.ErrUnsupported) {
		t.Errorf("algorithm: %v", err)
	}
	if _, _, _, err := Open(key040, f); !errors.Is(err, knx.ErrMalformed) {
		t.Errorf("plain frame: %v", err)
	}
	s, _ := Seal(key040, f, 1, GroupData)
	sync := s.Clone()
	sync.TPDU[2] = SCF{Service: SSyncReq}.Byte()
	if _, _, _, err := Open(key040, sync); !errors.Is(err, knx.ErrUnsupported) {
		t.Errorf("sync service: %v", err)
	}
	alg := s.Clone()
	alg.TPDU[2] = 0x50
	if _, _, _, err := Open(key040, alg); !errors.Is(err, knx.ErrUnsupported) {
		t.Errorf("algorithm: %v", err)
	}
	// An S-A_Data whose authenticated APDU is a single octet.
	one := f.Clone()
	one.TPDU = []byte{0x00, 0x00}
	s1, _ := Seal(key040, one, 1, SCF{Algorithm: AuthOnly})
	s1.TPDU = append(s1.TPDU[:9], s1.TPDU[10:]...)
	if _, _, _, err := Open(key040, s1); err == nil {
		t.Error("short plain APDU accepted")
	}
}

func TestTable(t *testing.T) {
	sender, _ := knx.ParseIndividualAddress("1.1.1")
	other, _ := knx.ParseIndividualAddress("1.1.2")
	g, plainG := group(t, "1/2/3"), group(t, "1/2/4")
	tx, err := NewTable(map[knx.GroupAddress]Key{g: key040}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	rx, _ := NewTable(map[knx.GroupAddress]Key{g: key040}, map[knx.IndividualAddress]uint64{sender: 99}, 0)
	if rx.Sequence() <= 100 {
		t.Errorf("initial sequence %d", rx.Sequence())
	}
	w, _ := apdu.GroupValueWrite(apdu.GroupValue{Small: true, Data: []byte{1}})
	f := cemi.NewGroupFrame(cemi.LDataInd, sender, g, knx.PriorityLow, w)
	s, err := tx.Outgoing(f)
	if err != nil || !IsSecure(s) || tx.Sequence() != 101 {
		t.Fatalf("outgoing: %v %d", err, tx.Sequence())
	}
	p, err := rx.Incoming(s)
	if err != nil || marshal(t, p) != marshal(t, f) {
		t.Fatalf("incoming: %v", err)
	}
	if _, err := rx.Incoming(s); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("replay: %v", err)
	}
	if _, err := rx.Incoming(f); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("plain to secured group: %v", err)
	}
	unknown := s.Clone()
	unknown.Source = other
	if _, err := rx.Incoming(unknown); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("unknown sender: %v", err)
	}
	rx.AddSender(other, 5)
	rx.AddSender(other, 1) // lower: kept at 5
	if _, err := rx.Incoming(unknown); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("sender changed, MAC must fail: %v", err)
	}
	// Plain frames to other groups and to individual addresses pass.
	pf := cemi.NewGroupFrame(cemi.LDataInd, sender, plainG, knx.PriorityLow, w)
	if out, err := tx.Outgoing(pf); err != nil || out != pf {
		t.Errorf("plain group outgoing: %v", err)
	}
	if out, err := rx.Incoming(pf); err != nil || out != pf {
		t.Errorf("plain group incoming: %v", err)
	}
	ind := cemi.NewIndividualFrame(cemi.LDataInd, sender, other, knx.PriorityLow, w)
	if out, err := tx.Outgoing(ind); err != nil || out != ind {
		t.Errorf("individual outgoing: %v", err)
	}
	secInd := s.Clone()
	secInd.Ctrl2 &^= cemi.Ctrl2GroupAddress
	if _, err := rx.Incoming(secInd); !errors.Is(err, knx.ErrUnsupported) {
		t.Errorf("point to point: %v", err)
	}
	noKey := s.Clone()
	noKey.Destination = uint16(plainG)
	if _, err := rx.Incoming(noKey); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("no key: %v", err)
	}
	tool, _ := Seal(key040, f, 500, SCF{ToolAccess: true, Algorithm: AuthConf})
	if _, err := rx.Incoming(tool); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tool access: %v", err)
	}
	bad := s.Clone()
	bad.TPDU[12] ^= 1
	if _, err := rx.Incoming(bad); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tampered: %v", err)
	}
	if _, err := NewTable(nil, nil, MaxSequence+1); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("sequence: %v", err)
	}
	full, _ := NewTable(map[knx.GroupAddress]Key{g: key040}, nil, MaxSequence+1-1)
	full.seq = MaxSequence + 1
	if _, err := full.Outgoing(f); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("exhausted: %v", err)
	}
}
