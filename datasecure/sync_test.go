// SPDX-License-Identifier: MIT

package datasecure

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
)

// Annex C.1 worked examples (tool 15.15.103, device 15.15.0, tool key
// 00..0f, T_Data_Connected sequence 0), as reproduced by xknx's open
// S-A_Sync work.
var (
	annexTool   = knx.MustParseIndividualAddress("15.15.103")
	annexDevice = knx.MustParseIndividualAddress("15.15.0")
	annexKey    = Key{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	annexChal   = [6]byte{0, 0, 0, 0, 0, 3}
)

const (
	annexSyncReq = "03f192000000000001000000000000c1cf4506f09bd79fab55"
	annexSyncRes = "03f193aaaaaaaaaaa99c023ad25e146470693e638d5b70cac4"
)

func TestSyncAnnexVectors(t *testing.T) {
	req, err := SyncRequest(annexKey, cemi.LDataReq, annexTool, annexDevice, 0x40, 1, [6]byte{}, annexChal)
	if err != nil {
		t.Fatal(err)
	}
	// The TPDU of the example carries the connected TPCI 43.
	if got := hex.EncodeToString(req.TPDU); got != "43"+annexSyncReq[2:] {
		t.Errorf("S-A_Sync_Req %s", got)
	}
	r, err := OpenSyncRequest(annexKey, req)
	if err != nil || r.Sequence != 1 || r.Challenge != annexChal || r.Serial != ([6]byte{}) {
		t.Fatalf("open request: %+v %v", r, err)
	}
	res, err := SyncResponse(annexKey, cemi.LDataReq, annexDevice, annexTool, 0x40, annexChal, [6]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(res.TPDU); got != "43"+annexSyncRes[2:] {
		t.Errorf("S-A_Sync_Res %s", got)
	}
	remote, local, err := OpenSyncResponse(annexKey, res, annexChal)
	if err != nil || remote != 3 || local != 4 {
		t.Fatalf("open response: %d %d %v", remote, local, err)
	}
	if _, _, err := OpenSyncResponse(Key{}, res, annexChal); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := OpenSyncRequest(annexKey, res); !errors.Is(err, knx.ErrMalformed) {
		t.Errorf("response as request: %v", err)
	}
	if _, _, err := OpenSyncResponse(annexKey, req, annexChal); !errors.Is(err, knx.ErrMalformed) {
		t.Errorf("request as response: %v", err)
	}
}

// A request of Calimero tools 3.0-M1 (5.0.1 to the surrogate 4.0.9 of
// xknx's SecureTest keyring), captured on secure routing.
func TestSyncCalimeroCapture(t *testing.T) {
	b, _ := hex.DecodeString("29003060500140091803F19200000000000100000000000083A5653559F78F0464FC")
	f, err := cemi.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	toolKey := Key{0x37, 0xf8, 0x0b, 0x3c, 0x96, 0xab, 0x13, 0xfa, 0x0b, 0x1c, 0x7a, 0x31, 0x23, 0xef, 0x80, 0x59}
	r, err := OpenSyncRequest(toolKey, f.(*cemi.LData))
	if err != nil {
		t.Fatal(err)
	}
	if r.Sequence != 1 || r.Serial != ([6]byte{}) {
		t.Errorf("request %+v", r)
	}
	if _, err := SyncRequest(annexKey, cemi.LDataReq, annexTool, annexDevice, 0, MaxSequence+1, [6]byte{}, annexChal); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("sequence: %v", err)
	}
	if _, err := SyncResponse(annexKey, cemi.LDataReq, annexDevice, annexTool, 0, annexChal, [6]byte{}, MaxSequence+1, 0); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("sequence: %v", err)
	}
}

// TestSurrogate plays a tool that syncs with the table's device and sends
// it a tool access frame, as Calimero tools do before a secured group
// write.
func TestSurrogate(t *testing.T) {
	tool, dev := knx.MustParseIndividualAddress("15.15.240"), knx.MustParseIndividualAddress("15.15.255")
	toolKey := Key{7}
	tab, _ := NewTable(nil, nil, 100)
	tab.SetToolKey(dev, toolKey)
	challenge := [6]byte{1, 2, 3, 4, 5, 6}
	req, _ := SyncRequest(toolKey, cemi.LDataInd, tool, dev, 0, 1, [6]byte{}, challenge)

	// Not for this device, or not a request: no answer.
	if res, err := tab.Respond(req, tool, cemi.LDataInd); res != nil || err != nil {
		t.Fatalf("request to another device: %v %v", res, err)
	}
	res, err := tab.Respond(req, dev, cemi.LDataInd)
	if err != nil || res == nil {
		t.Fatalf("respond: %v", err)
	}
	remote, local, err := OpenSyncResponse(toolKey, res, challenge)
	if err != nil || remote != 100 || local != 1 {
		t.Fatalf("response %d %d %v", remote, local, err)
	}
	// The first tool frame reuses the request's sequence number once.
	data := cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, []byte{0x01, 0xD4, 0, 9, 0, 0x10, 0x42})
	sealed, _ := Seal(toolKey, data, 1, SCF{ToolAccess: true, Algorithm: AuthConf})
	plain, err := tab.OpenTool(sealed, dev)
	if err != nil || plain == nil || plain.TPDU[1] != 0xD4 {
		t.Fatalf("tool frame: %v", err)
	}
	if _, err := tab.OpenTool(sealed, dev); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("replayed tool frame: %v", err)
	}
	next, _ := Seal(toolKey, data, 2, SCF{ToolAccess: true, Algorithm: AuthConf})
	if p, err := tab.OpenTool(next, dev); err != nil || p == nil {
		t.Errorf("next tool frame: %v", err)
	}
	// The device answers with its own tool key and sequence number.
	answer := cemi.NewIndividualFrame(cemi.LDataInd, dev, tool, knx.PrioritySystem, []byte{0x01, 0xD6, 0, 9, 0, 0x10, 0x42, 0})
	sa, err := tab.SealTool(answer)
	if err != nil {
		t.Fatal(err)
	}
	if p, seq, scf, err := Open(toolKey, sa); err != nil || seq != 100 || !scf.ToolAccess || p.TPDU[1] != 0xD6 {
		t.Errorf("answer %v %d %+v", err, seq, scf)
	}

	// Errors: no tool key, bad MAC, plain frames.
	other, _ := NewTable(nil, nil, 1)
	if _, err := other.Respond(req, dev, cemi.LDataInd); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("no tool key: %v", err)
	}
	if _, err := other.OpenTool(sealed, dev); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tool frame without tool key: %v", err)
	}
	if _, err := other.SealTool(answer); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("seal without tool key: %v", err)
	}
	bad := req.Clone()
	bad.TPDU[20] ^= 1
	if _, err := tab.Respond(bad, dev, cemi.LDataInd); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tampered request: %v", err)
	}
	badTool := sealed.Clone()
	badTool.TPDU[12] ^= 1
	if _, err := tab.OpenTool(badTool, dev); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("tampered tool frame: %v", err)
	}
	if p, err := tab.OpenTool(data, dev); p != nil || err != nil {
		t.Errorf("plain frame: %v %v", p, err)
	}
	group, _ := Seal(toolKey, cemi.NewGroupFrame(cemi.LDataInd, tool, 1, knx.PriorityLow, []byte{0, 0x80}), 3, GroupData)
	if p, err := tab.OpenTool(group, dev); p != nil || err != nil {
		t.Errorf("group frame: %v %v", p, err)
	}
	noTool, _ := Seal(toolKey, data, 9, GroupData)
	if p, err := tab.OpenTool(noTool, dev); p != nil || err != nil {
		t.Errorf("frame without tool access: %v %v", p, err)
	}
}
