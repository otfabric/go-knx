// SPDX-License-Identifier: MIT

package server_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/server"
)

// Each tap gets its own copy of the frame: a tap that changes it changes
// neither what another tap sees nor what the server distributes.
func TestTapGetsCopy(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	a, b := dialRaw(t, s), dialRaw(t, s)
	var mu sync.Mutex
	var seen [][]byte
	frames := map[*cemi.LData]bool{}
	for range 2 {
		s.Subscribe(func(tg server.Telegram) {
			if tg.Origin != server.FromTunnel {
				return
			}
			// What the tap sees, then a change of its frame.
			b, err := cemi.Marshal(tg.Frame)
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			seen = append(seen, b)
			frames[tg.Frame] = true
			mu.Unlock()
			tg.Frame.TPDU[len(tg.Frame.TPDU)-1] ^= 0xFF
			tg.Frame.Source = 0
		})
	}
	sent := write(ga, 0x21)
	a.request(0, sent)
	f := b.nextFrame()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || len(frames) != 2 {
		t.Fatalf("%d frames seen by the taps, %d distinct, want 2 and 2", len(seen), len(frames))
	}
	if !bytes.Equal(seen[0], seen[1]) {
		t.Errorf("the taps saw % X and % X, want the same frame", seen[0], seen[1])
	}
	if lastOctet(f) != 0x21 || f.Source == 0 {
		t.Errorf("the other client received %s after the taps changed their frames, want the value 21 from the sender's address", f)
	}
}
