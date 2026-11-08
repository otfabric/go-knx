// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/internal/capture"
)

// replayLink answers the client's frames with recorded ones: answer
// returns the frames to deliver after a sent frame.
type replayLink struct {
	in     chan cemi.Frame
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	sent   []*cemi.LData
	answer func(*cemi.LData) []*cemi.LData
}

func newReplayLink(answer func(*cemi.LData) []*cemi.LData) *replayLink {
	return &replayLink{in: make(chan cemi.Frame, 1024), done: make(chan struct{}), answer: answer}
}

func (l *replayLink) Send(_ context.Context, f cemi.Frame) error {
	ld, ok := f.(*cemi.LData)
	if !ok {
		return nil
	}
	l.mu.Lock()
	l.sent = append(l.sent, ld.Clone())
	l.mu.Unlock()
	if l.answer != nil {
		for _, a := range l.answer(ld) {
			l.in <- a
		}
	}
	return nil
}

func (l *replayLink) Receive(ctx context.Context) (cemi.Frame, error) {
	select {
	case f := <-l.in:
		return f, nil
	case <-l.done:
		return nil, knx.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *replayLink) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *replayLink) tpdus() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out [][]byte
	for _, f := range l.sent {
		out = append(out, f.TPDU)
	}
	return out
}

var captureTool = knx.MustParseIndividualAddress("1.1.102")

// TestCaptureDescriptorRead runs the client's DescriptorRead, in a
// transport connection, against every A_DeviceDescriptor_Read the
// management tool sent to the devices of a real TP1 installation
// (knx-datasets): the link answers the client's request with the
// device's recorded answers (T_ACK, then A_DeviceDescriptor_Response).
// The client must return the recorded descriptor, and send what the
// recorded tool sent: T_Connect, the request, a T_ACK of the answer and,
// on Close, T_Disconnect.
func TestCaptureDescriptorRead(t *testing.T) {
	want := map[string]int{
		"knx-datasets/attack-tool_residential-tp1_line-scan.pcapng":   55,
		"knx-datasets/attack-tool_residential-tp1_device-info.pcapng": 90,
	}
	masks := map[uint16]int{}
	for file, n := range want {
		f, err := capture.Load(file)
		if err != nil {
			t.Fatal(err)
		}
		got := 0
		for _, ex := range capture.Exchanges(f.TP, captureTool) {
			p, err := apdu.Parse(ex.Request.TPDU)
			if err != nil || p.APCI != apdu.DeviceDescriptorReadService || p.TPCI.Kind != apdu.TDataConnected || len(ex.Answers) != 2 {
				continue
			}
			res, err := apdu.Parse(ex.Answers[1].TPDU)
			if err != nil || res.APCI != apdu.DeviceDescriptorResponseService {
				t.Fatalf("%s: answers %v", ex.Request, ex.Answers)
			}
			recorded := binary.BigEndian.Uint16(res.Data)
			link := newReplayLink(func(sent *cemi.LData) []*cemi.LData {
				if !bytes.Equal(sent.TPDU, ex.Request.TPDU) {
					return nil
				}
				out := make([]*cemi.LData, len(ex.Answers))
				for i, a := range ex.Answers {
					out[i] = a.Clone()
				}
				return out
			})
			c := client.New(link, client.WithSource(captureTool))
			d := c.Device(ex.Device, client.Connected())
			v, err := d.DescriptorRead(ctx(t))
			if err != nil || v != recorded {
				t.Fatalf("%s: descriptor %04X %v, recorded %04X", ex.Device, v, err, recorded)
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
			sent := link.tpdus()
			if exp := [][]byte{{0x80}, ex.Request.TPDU, {0xC2}, {0x81}}; !equalTPDUs(sent, exp) {
				t.Fatalf("%s: sent % X, recorded tool % X", ex.Device, sent, exp)
			}
			for _, s := range link.sent {
				if s.Source != captureTool || knx.IndividualAddress(s.Destination) != ex.Device || s.IsGroup() || s.Priority() != knx.PrioritySystem {
					t.Fatalf("sent %s", s)
				}
			}
			masks[recorded]++
			got++
		}
		if got != n {
			t.Errorf("%s: %d descriptor reads, want %d", file, got, n)
		}
	}
	t.Logf("descriptors read: %v", masks)
}

func equalTPDUs(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// TestCaptureGroupTelegrams delivers every group telegram recorded on the
// TP1 line of a house (five weeks) to the client: each becomes a Telegram
// with the recorded source, group, service and value.
func TestCaptureGroupTelegrams(t *testing.T) {
	f, err := capture.Load("knx-datasets/unknown_residential-tp1_all-knx.pcapng")
	if err != nil {
		t.Fatal(err)
	}
	var frames []*cemi.LData
	for _, fr := range f.TP {
		ld, err := cemi.ParseTP1(fr.Data)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, ld)
	}
	link := newReplayLink(nil)
	c := client.New(link, client.WithSource(captureTool))
	defer func() { _ = c.Close() }()
	var (
		mu       sync.Mutex
		got      []client.Telegram
		services = map[apdu.APCI]int{}
		all      = make(chan struct{})
	)
	c.OnTelegram(func(tg client.Telegram) {
		mu.Lock()
		got = append(got, tg)
		services[tg.Service]++
		if len(got) == len(frames) {
			close(all)
		}
		mu.Unlock()
	})
	go func() {
		for _, ld := range frames {
			link.in <- ld
		}
	}()
	select {
	case <-all:
	case <-ctx(t).Done():
		t.Fatalf("%d of %d telegrams", len(got), len(frames))
	}
	mu.Lock()
	defer mu.Unlock()
	for i, tg := range got {
		ld := frames[i]
		g, _ := ld.Group()
		svc, v, err := apdu.ParseGroupValue(ld.TPDU)
		if err != nil || tg.Source != ld.Source || tg.Group != g || tg.Service != svc || !bytes.Equal(tg.Value.Data, v.Data) || tg.Value.Small != v.Small {
			t.Fatalf("telegram %d: %+v, frame %s", i, tg, ld)
		}
	}
	if services[apdu.GroupValueWriteService] != 379871 || services[apdu.GroupValueResponseService] != 3 || services[apdu.GroupValueReadService] != 1 {
		t.Fatalf("services %v", services)
	}
}
