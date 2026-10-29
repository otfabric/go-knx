// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/dpt"
	"github.com/otfabric/go-knx/internal/leak"
)

const wait = 2 * time.Second

var (
	g1  = knx.MustParseGroupAddress("1/2/3")
	g2  = knx.MustParseGroupAddress("1/2/4")
	src = knx.MustParseIndividualAddress("1.1.5")
)

// link is a fake client.Link.
type link struct {
	mu       sync.Mutex
	sent     []*cemi.LData
	sendErr  error
	closeErr error
	onSend   func(l *link, f *cemi.LData)

	in      chan cemi.Frame
	fail    chan error
	closed  chan struct{}
	closeMu sync.Once
}

func newLink() *link {
	return &link{in: make(chan cemi.Frame, 64), fail: make(chan error, 1), closed: make(chan struct{})}
}

func (l *link) Send(_ context.Context, f cemi.Frame) error {
	ld := f.(*cemi.LData)
	l.mu.Lock()
	l.sent = append(l.sent, ld)
	err, on := l.sendErr, l.onSend
	l.mu.Unlock()
	if err != nil {
		return err
	}
	if on != nil {
		on(l, ld)
	}
	return nil
}

func (l *link) Receive(ctx context.Context) (cemi.Frame, error) {
	select {
	case f := <-l.in:
		return f, nil
	case err := <-l.fail:
		return nil, err
	case <-l.closed:
		return nil, knx.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *link) Close() error {
	l.closeMu.Do(func() { close(l.closed) })
	return l.closeErr
}

func (l *link) last(t *testing.T) *cemi.LData {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.sent) == 0 {
		t.Fatal("nothing sent")
	}
	return l.sent[len(l.sent)-1]
}

func ind(g knx.GroupAddress, from knx.IndividualAddress, tpdu []byte) *cemi.LData {
	return cemi.NewGroupFrame(cemi.LDataInd, from, g, knx.PriorityLow, tpdu)
}

func resp(t testing.TB, g knx.GroupAddress, from knx.IndividualAddress, v apdu.GroupValue) *cemi.LData {
	b, err := apdu.GroupValueResponse(v)
	if err != nil {
		t.Fatal(err)
	}
	return ind(g, from, b)
}

func wr(t testing.TB, g knx.GroupAddress, v apdu.GroupValue) *cemi.LData {
	b, err := apdu.GroupValueWrite(v)
	if err != nil {
		t.Fatal(err)
	}
	return ind(g, src, b)
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func newClient(t *testing.T, opts ...client.Option) (*client.Client, *link) {
	t.Helper()
	l := newLink()
	c := client.New(l, opts...)
	t.Cleanup(func() { c.Close() })
	return c, l
}

// sync waits until the client's reader handled every frame pushed so
// far: it pushes a marker and waits for the hook to see it.
func flush(t *testing.T, c *client.Client, l *link) {
	t.Helper()
	marker := knx.MustParseGroupAddress("31/7/255")
	seen := make(chan struct{}, 1)
	remove := c.OnTelegram(func(tg client.Telegram) {
		if tg.Group == marker {
			select {
			case seen <- struct{}{}:
			default:
			}
		}
	})
	defer remove()
	l.in <- wr(t, marker, apdu.GroupValue{Data: []byte{0}, Small: true})
	select {
	case <-seen:
	case <-time.After(wait):
		t.Fatal("reader did not catch up")
	}
}

func TestGroupWrite(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t, client.WithSource(src), client.WithPriority(knx.PriorityNormal), client.WithLogger(nil))
	if c.Link() != client.Link(l) {
		t.Fatal("Link")
	}
	check := func(svc apdu.APCI, want apdu.GroupValue) {
		t.Helper()
		f := l.last(t)
		g, _ := f.Group()
		if f.MsgCode != cemi.LDataReq || g != g1 || f.Source != src || f.Priority() != knx.PriorityNormal {
			t.Fatalf("frame %v", f)
		}
		gotSvc, v, err := apdu.ParseGroupValue(f.TPDU)
		if err != nil || gotSvc != svc || v.Small != want.Small || string(v.Data) != string(want.Data) {
			t.Fatalf("value %v %+v %v, want %v %+v", gotSvc, v, err, svc, want)
		}
	}
	for _, tc := range []struct {
		v    any
		opts []client.WriteOption
		want apdu.GroupValue
	}{
		{true, nil, apdu.GroupValue{Data: []byte{1}, Small: true}},
		{false, nil, apdu.GroupValue{Data: []byte{0}, Small: true}},
		{[]byte{1, 2}, nil, apdu.GroupValue{Data: []byte{1, 2}}},
		{apdu.GroupValue{Data: []byte{3}, Small: true}, nil, apdu.GroupValue{Data: []byte{3}, Small: true}},
		{21.5, []client.WriteOption{client.WithDPT("9.001")}, apdu.GroupValue{Data: mustEncode(t, "9.001", 21.5)}},
		{true, []client.WriteOption{client.WithType(dpt.MustLookup("1.001"))}, apdu.GroupValue{Data: []byte{1}, Small: true}},
	} {
		if err := c.GroupWrite(ctx(t), g1, tc.v, tc.opts...); err != nil {
			t.Fatalf("GroupWrite(%v): %v", tc.v, err)
		}
		check(apdu.GroupValueWriteService, tc.want)
		if err := c.GroupRespond(ctx(t), g1, tc.v, tc.opts...); err != nil {
			t.Fatalf("GroupRespond(%v): %v", tc.v, err)
		}
		check(apdu.GroupValueResponseService, tc.want)
	}
	for name, tc := range map[string]struct {
		v    any
		opts []client.WriteOption
	}{
		"int without type": {42, nil},
		"unknown dpt":      {1, []client.WriteOption{client.WithDPT("999.999")}},
		"encode":           {"x", []client.WriteOption{client.WithDPT("9.001")}},
		"empty raw":        {[]byte{}, nil},
	} {
		if err := c.GroupWrite(ctx(t), g1, tc.v, tc.opts...); err == nil {
			t.Errorf("GroupWrite %s: no error", name)
		}
		if err := c.GroupRespond(ctx(t), g1, tc.v, tc.opts...); err == nil {
			t.Errorf("GroupRespond %s: no error", name)
		}
	}
	if err := c.GroupWrite(ctx(t), g1, 42); !errors.Is(err, knx.ErrInvalidValue) {
		t.Fatalf("int: %v", err)
	}
	l.mu.Lock()
	l.sendErr = knx.ErrConnectionLost
	l.mu.Unlock()
	if err := c.GroupWrite(ctx(t), g1, true); !errors.Is(err, knx.ErrConnectionLost) {
		t.Fatalf("link error: %v", err)
	}
}

func mustEncode(t *testing.T, id string, v any) []byte {
	t.Helper()
	b, err := dpt.MustLookup(id).Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// responder answers every read of g with v from each of froms.
func responder(t *testing.T, g knx.GroupAddress, v apdu.GroupValue, froms ...knx.IndividualAddress) func(*link, *cemi.LData) {
	return func(l *link, f *cemi.LData) {
		svc, _, err := apdu.ParseGroupValue(f.TPDU)
		if dst, _ := f.Group(); err != nil || svc != apdu.GroupValueReadService || dst != g {
			return
		}
		// Noise first: a response to another group, a write to g.
		l.in <- resp(t, g2, src, v)
		l.in <- wr(t, g, v)
		for _, from := range froms {
			l.in <- resp(t, g, from, v)
		}
	}
}

func TestGroupRead(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	raw := mustEncode(t, "9.001", 19.5)
	l.onSend = responder(t, g1, apdu.GroupValue{Data: raw}, src)

	// Without a deadline: the default timeout applies; the answer comes
	// at once.
	r, err := c.GroupRead(context.Background(), g1, client.WithDPT("9.001"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != src || r.Group != g1 || r.Service != apdu.GroupValueResponseService || r.Decoded != 19.5 {
		t.Fatalf("response %+v", r)
	}
	if v, err := r.Decode("9.001"); err != nil || v != 19.5 {
		t.Fatalf("Decode %v %v", v, err)
	}
	if _, err := r.Decode("999.1"); err == nil {
		t.Fatal("Decode with an unknown type")
	}
	if f := l.last(t); f.MsgCode != cemi.LDataReq {
		t.Fatalf("read frame %v", f)
	}
	// Raw.
	r, err = c.GroupRead(ctx(t), g1)
	if err != nil || r.Decoded != nil || string(r.Value.Data) != string(raw) {
		t.Fatalf("raw read %+v %v", r, err)
	}
	// Decode error.
	if _, err := c.GroupRead(ctx(t), g1, client.WithDPT("1.001")); err == nil {
		t.Fatal("decode of 2 octets as 1.001")
	}
	// Option error.
	if _, err := c.GroupRead(ctx(t), g1, client.WithDPT("999.999")); err == nil {
		t.Fatal("unknown type")
	}
	// Timeout: nobody answers g2.
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.GroupRead(short, g2); !errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("timeout: %v", err)
	}
	// Cancellation is not a timeout.
	cc, cancel2 := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel2() }()
	if _, err := c.GroupRead(cc, g2); !errors.Is(err, context.Canceled) || errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("cancel: %v", err)
	}
	// Send error.
	l.mu.Lock()
	l.sendErr = knx.ErrNotConfirmed
	l.mu.Unlock()
	if _, err := c.GroupRead(ctx(t), g1); !errors.Is(err, knx.ErrNotConfirmed) {
		t.Fatalf("send error: %v", err)
	}
}

func TestGroupReadAll(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	a, b := knx.MustParseIndividualAddress("1.1.1"), knx.MustParseIndividualAddress("1.1.2")
	l.onSend = responder(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true}, a, b)
	rs, err := c.GroupReadAll(ctx(t), g1, 100*time.Millisecond, client.WithDPT("1.001"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].Source != a || rs[1].Source != b || rs[0].Decoded != true {
		t.Fatalf("responses %+v", rs)
	}
	rs, err = c.GroupReadAll(ctx(t), g2, 30*time.Millisecond)
	if err != nil || len(rs) != 0 {
		t.Fatalf("no responders: %+v %v", rs, err)
	}
}

func TestReadEndsWithClient(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	errc := make(chan error, 1)
	l.onSend = func(l *link, f *cemi.LData) { go c.Close() }
	go func() { _, err := c.GroupRead(ctx(t), g1); errc <- err }()
	select {
	case err := <-errc:
		if !errors.Is(err, knx.ErrClosed) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(wait):
		t.Fatal("GroupRead did not return")
	}

	c2, l2 := newClient(t)
	boom := errors.New("boom")
	l2.onSend = func(l *link, f *cemi.LData) { l.fail <- boom }
	if _, err := c2.GroupRead(ctx(t), g1); !errors.Is(err, boom) {
		t.Fatalf("link failure: %v", err)
	}
}

func TestSubscribe(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	only1 := c.Subscribe(8, g1)
	all := c.Subscribe(0) // buffer 1
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true})
	l.in <- wr(t, g2, apdu.GroupValue{Data: []byte{2}, Small: true})
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{3}, Small: true})
	flush(t, c, l)
	var got []byte
	for len(only1.C()) > 0 {
		tg := <-only1.C()
		got = append(got, tg.Value.Data[0])
	}
	if string(got) != "\x01\x03" || only1.Dropped() != 0 {
		t.Fatalf("filtered %v dropped %d", got, only1.Dropped())
	}
	// all holds one; the rest (2 telegrams and the flush marker) dropped.
	if tg := <-all.C(); tg.Value.Data[0] != 1 || tg.Service != apdu.GroupValueWriteService || tg.Source != src || tg.Time.IsZero() {
		t.Fatalf("all: %+v", tg)
	}
	if all.Dropped() != 3 {
		t.Fatalf("dropped %d", all.Dropped())
	}
	only1.Unsubscribe()
	only1.Unsubscribe()
	if _, ok := <-only1.C(); ok {
		t.Fatal("channel open after Unsubscribe")
	}
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{4}, Small: true})
	flush(t, c, l)
}

func TestIgnoredFrames(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	sub := c.Subscribe(8)
	con := wr(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true})
	con.MsgCode = cemi.LDataCon
	l.in <- con
	l.in <- cemi.NewIndividualFrame(cemi.LDataInd, src, src, knx.PriorityLow, apdu.GroupValueRead())
	l.in <- ind(g1, src, []byte{0x03, 0x00}) // not a group value service
	l.in <- &cemi.Reset{MsgCode: cemi.MResetInd}
	flush(t, c, l)
	if tg := <-sub.C(); tg.Group != knx.MustParseGroupAddress("31/7/255") {
		t.Fatalf("delivered %+v", tg)
	}
}

func TestOnTelegram(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	var mu sync.Mutex
	n := 0
	remove := c.OnTelegram(func(client.Telegram) { mu.Lock(); n++; mu.Unlock() })
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true})
	flush(t, c, l)
	remove()
	l.in <- wr(t, g1, apdu.GroupValue{Data: []byte{1}, Small: true})
	flush(t, c, l)
	mu.Lock()
	defer mu.Unlock()
	if n != 2 { // the telegram and the first marker
		t.Fatalf("hook called %d times", n)
	}
}

func TestClose(t *testing.T) {
	leak.Check(t)
	l := newLink()
	l.closeErr = errors.New("close failed")
	c := client.New(l)
	sub := c.Subscribe(1)
	if err := c.Close(); err != l.closeErr {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("Done open")
	}
	if c.Err() != nil {
		t.Fatalf("Err %v", c.Err())
	}
	if _, ok := <-sub.C(); ok {
		t.Fatal("subscription open after Close")
	}
	late := c.Subscribe(1)
	if _, ok := <-late.C(); ok {
		t.Fatal("subscription after Close is open")
	}
	late.Unsubscribe()
	if _, err := c.GroupRead(ctx(t), g1); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("GroupRead after Close: %v", err)
	}
}

func TestLinkFailure(t *testing.T) {
	leak.Check(t)
	c, l := newClient(t)
	sub := c.Subscribe(1)
	boom := errors.New("boom")
	l.fail <- boom
	select {
	case <-c.Done():
	case <-time.After(wait):
		t.Fatal("Done not closed")
	}
	if !errors.Is(c.Err(), boom) {
		t.Fatalf("Err %v", c.Err())
	}
	if _, ok := <-sub.C(); ok {
		t.Fatal("subscription open")
	}
	// A link that ends with ErrClosed is a normal end.
	c2, l2 := newClient(t)
	l2.fail <- knx.ErrClosed
	<-c2.Done()
	if c2.Err() != nil {
		t.Fatalf("Err %v", c2.Err())
	}
}
