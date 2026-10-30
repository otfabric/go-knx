// SPDX-License-Identifier: MIT

package client_test

import (
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/datasecure"
)

// TestSurrogate: a tool (Calimero tools' sequence) syncs with the client,
// then asks it by group object diagnostics to send a secured group write.
func TestSurrogate(t *testing.T) {
	tool, own := knx.MustParseIndividualAddress("15.15.240"), knx.MustParseIndividualAddress("15.15.255")
	toolKey, groupKey := datasecure.Key{7}, datasecure.Key{0x42}
	g := knx.MustParseGroupAddress("1/2/9")
	tab, _ := datasecure.NewTable(map[knx.GroupAddress]datasecure.Key{g: groupKey}, map[knx.IndividualAddress]uint64{tool: 0}, 50)
	tab.SetToolKey(own, toolKey)
	l := newLink()
	c := client.New(l, client.WithSource(own), client.WithDataSecure(tab))
	defer c.Close()
	sub := c.Subscribe(4, g)

	challenge := [6]byte{9, 9, 9, 9, 9, 9}
	req, _ := datasecure.SyncRequest(toolKey, cemi.LDataInd, tool, own, 0, 1, [6]byte{}, challenge)
	l.in <- req
	waitSent(t, l, 1)
	if _, local, err := datasecure.OpenSyncResponse(toolKey, l.last(t), challenge); err != nil || local != 1 {
		t.Fatalf("sync response: %d %v", local, err)
	}

	cmd := cemi.NewIndividualFrame(cemi.LDataInd, tool, own, knx.PrioritySystem,
		[]byte{0x01, 0xD4, 0x00, 0x09, 0x00, 0x10, 0x42, 0x00, 0x01, 0x03, 0x0A, 0x09, 0x0C, 0x97})
	sealed, _ := datasecure.Seal(toolKey, cmd, 1, datasecure.SCF{ToolAccess: true, Algorithm: datasecure.AuthConf})
	l.in <- sealed
	waitSent(t, l, 3)
	l.mu.Lock()
	write, answer := l.sent[1], l.sent[2]
	l.mu.Unlock()
	if gw, ok := write.Group(); !ok || gw != g || !datasecure.IsSecure(write) || write.Source != own {
		t.Fatalf("group write %s", write)
	}
	plainW, _, _, err := datasecure.Open(groupKey, write)
	if err != nil {
		t.Fatal(err)
	}
	if svc, v, _ := apdu.ParseGroupValue(plainW.TPDU); svc != apdu.GroupValueWriteService || string(v.Data) != "\x0c\x97" {
		t.Errorf("group write %v % X", svc, v.Data)
	}
	select {
	case tg := <-sub.C():
		if tg.Source != own || !tg.Secure || string(tg.Value.Data) != "\x0c\x97" {
			t.Errorf("local delivery %+v", tg)
		}
	case <-time.After(wait):
		t.Error("the surrogate's write was not delivered locally")
	}
	plainA, _, scf, err := datasecure.Open(toolKey, answer)
	if err != nil || !scf.ToolAccess || knx.IndividualAddress(answer.Destination) != tool {
		t.Fatalf("answer %v %+v", err, scf)
	}
	if got := plainA.TPDU; len(got) != 10 || got[1] != 0xD6 || got[7] != 0x00 || got[8] != 0x00 || got[9] != 0x01 {
		t.Errorf("answer % X", got)
	}

	// Other tool requests are answered with "command invalid" or not at all.
	read := cemi.NewIndividualFrame(cemi.LDataInd, tool, own, knx.PrioritySystem,
		[]byte{0x01, 0xD4, 0x00, 0x09, 0x00, 0x10, 0x42, 0x00, 0x02, 0x03, 0x0A, 0x09})
	sealedRead, _ := datasecure.Seal(toolKey, read, 2, datasecure.SCF{ToolAccess: true, Algorithm: datasecure.AuthConf})
	l.in <- sealedRead
	waitSent(t, l, 4)
	if p, _, _, err := datasecure.Open(toolKey, l.last(t)); err != nil || p.TPDU[7] != 0xF2 {
		t.Errorf("unsupported command answer % X %v", p.TPDU, err)
	}
	other := cemi.NewIndividualFrame(cemi.LDataInd, tool, own, knx.PrioritySystem, []byte{0x03, 0xD5, 0, 0, 0, 0})
	sealedOther, _ := datasecure.Seal(toolKey, other, 3, datasecure.SCF{ToolAccess: true, Algorithm: datasecure.AuthConf})
	l.in <- sealedOther
	// Frames that fail: replay, plain individual frames.
	l.in <- sealed
	l.in <- cmd
	time.Sleep(100 * time.Millisecond)
	l.mu.Lock()
	n := len(l.sent)
	l.mu.Unlock()
	if n != 4 {
		t.Errorf("%d frames sent, want 4", n)
	}
}

func waitSent(t *testing.T, l *link, n int) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		l.mu.Lock()
		got := len(l.sent)
		l.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d frames sent, want %d", got, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
