// SPDX-License-Identifier: MIT

package client_test

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/internal/leak"
)

// Every subscription, callback and pending read gets its own copy of a
// telegram, frame and value: what one consumer changes in its copy, the
// others do not see.
func TestTelegramCopiesPerConsumer(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	a, b := c.Subscribe(1, g1), c.Subscribe(1, g1)
	hooked := make(chan client.Telegram, 1)
	remove := c.OnTelegram(func(tg client.Telegram) {
		if tg.Group == g1 {
			hooked <- tg
		}
	})
	read := make(chan client.Response, 1)
	go func() {
		r, err := c.GroupRead(ctx(t), g1)
		if err != nil {
			t.Error(err)
		}
		read <- r
	}()
	waitSent(t, l, 1) // the read request is on the link
	in := resp(t, g1, src, apdu.GroupValue{Data: []byte{0x12, 0x34}})
	want := append([]byte(nil), in.TPDU...)
	l.in <- in

	ta := recv(t, a.C(), "the telegram on the first subscription")
	tb := recv(t, b.C(), "the telegram on the second subscription")
	th := recv(t, hooked, "the telegram of the callback")
	tr := recv(t, read, "the response of the read").Telegram
	remove()

	// The first subscription changes its copy.
	ta.Frame.TPDU[2] = 0
	ta.Value.Data[1] = 0
	ta.Frame.Source = 0
	for name, tg := range map[string]client.Telegram{"second subscription": tb, "callback": th, "read": tr} {
		if tg.Frame == ta.Frame || !bytes.Equal(tg.Frame.TPDU, want) || tg.Frame.Source != src {
			t.Errorf("%s: frame %s after the first subscription changed its telegram, want TPDU % X from %s", name, tg.Frame, want, src)
		}
		if !bytes.Equal(tg.Value.Data, []byte{0x12, 0x34}) {
			t.Errorf("%s: value % X after the first subscription changed its telegram, want 12 34", name, tg.Value.Data)
		}
	}
	if !bytes.Equal(in.TPDU, want) {
		t.Errorf("the link's frame has TPDU % X, want % X", in.TPDU, want)
	}

	// A callback that changes its copy changes nothing the subscription
	// receives after it.
	remove = c.OnTelegram(func(tg client.Telegram) {
		if tg.Group == g1 {
			tg.Frame.TPDU[2] ^= 0xFF
			tg.Value.Data[0] ^= 0xFF
			hooked <- tg
		}
	})
	defer remove()
	l.in <- resp(t, g1, src, apdu.GroupValue{Data: []byte{0x56, 0x78}})
	recv(t, hooked, "the second telegram of the callback")
	tb = recv(t, b.C(), "the second telegram on the second subscription")
	recv(t, a.C(), "the second telegram on the first subscription")
	if tb.Frame.TPDU[2] != 0x56 || tb.Value.Data[0] != 0x56 {
		t.Errorf("subscription: TPDU % X, value % X after a callback changed its telegram, want 56 in both", tb.Frame.TPDU, tb.Value.Data)
	}
}
