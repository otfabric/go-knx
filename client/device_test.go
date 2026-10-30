// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/mgmt"
	"github.com/otfabric/go-knx/server"
)

var serverAddress = knx.MustParseIndividualAddress("1.1.0")

func startManagedServer(t testing.TB, opts ...server.Option) *server.Server {
	t.Helper()
	s, err := server.New(append([]server.Option{server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false),
		server.WithIndividualAddress(serverAddress), server.WithName("managed"),
		server.WithTunnelAddresses(knx.MustParseIndividualAddress("1.1.10"), knx.MustParseIndividualAddress("1.1.11"))}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// manage reads and writes the server's device: the serial number, the IO
// list, the friendly name (written, then read back), the descriptor, a
// refused property.
func manage(t *testing.T, d *client.Device, objects int) {
	t.Helper()
	serial, err := d.PropertyRead(ctx(t), 0, 11, 1, 1)
	if err != nil || len(serial) != 6 {
		t.Fatalf("serial % X %v", serial, err)
	}
	if n, err := d.PropertyElements(ctx(t), 0, 71); err != nil || n != objects {
		t.Fatalf("IO list %d %v", n, err)
	}
	got, err := d.PropertyWrite(ctx(t), 2, 76, 1, 4, []byte("tool"))
	if err != nil || string(got) != "tool" {
		t.Fatalf("write name %q %v", got, err)
	}
	name, err := d.PropertyRead(ctx(t), 2, 76, 1, 7)
	if err != nil || string(name) != "toolged" {
		t.Fatalf("name %q %v", name, err)
	}
	if v, err := d.DescriptorRead(ctx(t)); err != nil || v != server.DeviceDescriptor {
		t.Fatalf("descriptor %04X %v", v, err)
	}
	var pe *mgmt.PropertyError
	if _, err := d.PropertyRead(ctx(t), 0, 200, 1, 1); !errors.As(err, &pe) || !errors.Is(err, knx.ErrRejected) || pe.PID != 200 {
		t.Fatalf("missing property: %v", err)
	}
	if _, err := d.PropertyWrite(ctx(t), 0, 11, 1, 1, make([]byte, 6)); !errors.Is(err, knx.ErrRejected) {
		t.Fatalf("read only property: %v", err)
	}
}

func TestDevicePlain(t *testing.T) {
	leak.Check(t)
	for _, connected := range []bool{false, true} {
		s := startManagedServer(t)
		c := dialClient(t, s)
		var opts []client.DeviceOption
		if connected {
			opts = append(opts, client.Connected())
		}
		d := c.Device(serverAddress, opts...)
		manage(t, d, 3)
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		c.Close()
		s.Close()
	}
}

func TestDeviceSecure(t *testing.T) {
	leak.Check(t)
	key := datasecure.Key{0x74, 0x6f, 0x6f, 0x6c}
	for _, connected := range []bool{false, true} {
		s := startManagedServer(t, server.WithToolKey(key))
		c := dialClient(t, s)

		// Plain access to the secured device is not answered.
		plain := c.Device(serverAddress)
		short, cancel := context.WithTimeout(ctx(t), 300*time.Millisecond)
		if _, err := plain.PropertyRead(short, 0, 11, 1, 1); !errors.Is(err, knx.ErrTimeout) {
			t.Fatalf("plain access: %v", err)
		}
		cancel()
		plain.Close()

		// A wrong tool key: the S-A_Sync is not answered.
		wrong := c.Device(serverAddress, client.WithToolKey(datasecure.Key{1}))
		short, cancel = context.WithTimeout(ctx(t), 300*time.Millisecond)
		if _, err := wrong.PropertyRead(short, 0, 11, 1, 1); !errors.Is(err, knx.ErrTimeout) {
			t.Fatalf("wrong key: %v", err)
		}
		cancel()
		wrong.Close()

		opts := []client.DeviceOption{client.WithToolKey(key)}
		if connected {
			opts = append(opts, client.Connected())
		}
		d := c.Device(serverAddress, opts...)
		if !d.Secured() {
			t.Fatal("not secured")
		}
		manage(t, d, 4)
		if mode, err := d.PropertyRead(ctx(t), 3, mgmt.PIDSecurityMode, 1, 1); err != nil || len(mode) != 1 || mode[0] != 1 {
			t.Fatalf("security mode % X %v", mode, err)
		}
		d.Close()

		// A new session synchronises again; its sequence numbers continue.
		tab, _ := datasecure.NewTable(nil, nil, 0)
		tab.SetToolKey(serverAddress, key)
		c2, err := client.DialTunnel(ctx(t), s.Addr().String(), nil, client.WithDataSecure(tab))
		if err != nil {
			t.Fatal(err)
		}
		d2 := c2.Device(serverAddress)
		if !d2.Secured() {
			t.Fatal("tool key of the Data Secure table not used")
		}
		if _, err := d2.PropertyRead(ctx(t), 0, 11, 1, 1); err != nil {
			t.Fatal(err)
		}
		d2.Close()
		c2.Close()
		c.Close()
		s.Close()
	}
}

// scripted answers the frames a Device sends to the device at addr.
func scripted(l *link, f func(l *link, tp apdu.TPDU, n int)) {
	n := 0
	l.onSend = func(l *link, ld *cemi.LData) {
		tp, err := apdu.Parse(ld.TPDU)
		if err != nil {
			return
		}
		n++
		f(l, tp, n)
	}
}

func from(tp apdu.TPDU) *cemi.LData {
	return cemi.NewIndividualFrame(cemi.LDataInd, serverAddress, src, knx.PrioritySystem, tp.Bytes())
}

func TestDeviceTransport(t *testing.T) {
	defer client.SetAckTimeout(50 * time.Millisecond)()
	descriptor := apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TDataConnected}, APCI: apdu.DeviceDescriptorResponseService, Data: []byte{0x07, 0xB0}}

	// No acknowledgement, then T_NAK, then T_ACK and the answer, which
	// the device repeats: the client repeats its request, acknowledges
	// the answer twice and returns it.
	l := newLink()
	c := client.New(l, client.WithSource(src))
	scripted(l, func(l *link, tp apdu.TPDU, n int) {
		if tp.TPCI.Kind != apdu.TDataConnected {
			return
		}
		switch n {
		case 3:
			l.in <- from(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TNak}})
		case 4:
			l.in <- from(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TAck}})
			l.in <- from(descriptor)
			l.in <- from(descriptor)
		}
	})
	d := c.Device(serverAddress, client.Connected())
	if d.Address() != serverAddress || d.Secured() {
		t.Fatal("device")
	}
	if v, err := d.DescriptorRead(ctx(t)); err != nil || v != 0x07B0 {
		t.Fatalf("descriptor %04X %v", v, err)
	}
	time.Sleep(50 * time.Millisecond)
	d.Close()
	acks := 0
	l.mu.Lock()
	for _, f := range l.sent {
		if tp, _ := apdu.Parse(f.TPDU); tp.TPCI.Kind == apdu.TAck {
			acks++
		}
	}
	l.mu.Unlock()
	if acks != 2 {
		t.Errorf("%d acknowledgements, want 2", acks)
	}
	if tp, _ := apdu.Parse(l.last(t).TPDU); tp.TPCI.Kind != apdu.TDisconnect {
		t.Errorf("close sent %+v", tp)
	}
	c.Close()

	// The device closes the connection.
	l = newLink()
	c = client.New(l, client.WithSource(src))
	scripted(l, func(l *link, tp apdu.TPDU, _ int) {
		if tp.TPCI.Kind == apdu.TDataConnected {
			l.in <- from(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TDisconnect}})
		}
	})
	d = c.Device(serverAddress, client.Connected())
	if _, err := d.PropertyRead(ctx(t), 0, 11, 1, 1); !errors.Is(err, knx.ErrConnectionLost) {
		t.Fatalf("disconnect: %v", err)
	}
	// Never acknowledged: a timeout after the repetitions.
	scripted(l, func(*link, apdu.TPDU, int) {})
	if _, err := d.PropertyRead(ctx(t), 0, 11, 1, 1); !errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("no acknowledgement: %v", err)
	}
	// Invalid requests.
	if _, err := d.PropertyRead(ctx(t), 0, 11, 1, 0); !errors.Is(err, knx.ErrInvalidValue) {
		t.Fatalf("count 0: %v", err)
	}
	c.Close()

	// Connectionless: a refused descriptor type, malformed element
	// counts, an empty positive answer.
	l = newLink()
	c = client.New(l, client.WithSource(src))
	scripted(l, func(l *link, tp apdu.TPDU, _ int) {
		switch tp.APCI {
		case apdu.DeviceDescriptorReadService:
			l.in <- from(apdu.TPDU{APCI: apdu.DeviceDescriptorResponseService, Short: 0x3F})
		case apdu.PropertyValueReadService:
			p, _ := mgmt.ParseProperty(tp)
			p.Data = []byte{1}
			l.in <- from(apdu.TPDU{APCI: apdu.PropertyValueResponseService, Data: mgmt.Property{Object: p.Object, PID: p.PID, Start: p.Start, Count: p.Count, Data: p.Data}.TPDU(apdu.TPCI{}, apdu.PropertyValueResponseService)[2:]})
		default:
		}
	})
	d = c.Device(serverAddress)
	if _, err := d.DescriptorRead(ctx(t)); !errors.Is(err, knx.ErrRejected) {
		t.Fatalf("refused descriptor: %v", err)
	}
	if _, err := d.PropertyElements(ctx(t), 0, 71); !errors.Is(err, knx.ErrMalformed) {
		t.Fatalf("element count: %v", err)
	}
	c.Close()
}
