// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/mgmt"
	"github.com/otfabric/go-knx/routing"
)

// Transport layer timing of a connection: the acknowledgement timeout,
// the repetitions of a data PDU, and the idle time after which the
// device has closed the connection (6 s at the device).
var ackTimeout = 3 * time.Second

const (
	maxRepetitions = 3
	idleReconnect  = 5 * time.Second
)

// DeviceOption configures a Device.
type DeviceOption func(*Device)

// Connected accesses the device in a transport layer connection
// (T_Connect, numbered and acknowledged data, T_Disconnect) instead of
// connectionless.
func Connected() DeviceOption { return func(d *Device) { d.connected = true } }

// WithToolKey secures the access with the device's tool key (KNX Data
// Secure point to point with tool access): an S-A_Sync before the first
// request, then S-A_Data. Without this option the access is secured when
// the client's Data Secure table (WithDataSecure) has the device's tool
// key.
func WithToolKey(k datasecure.Key) DeviceOption {
	return func(d *Device) {
		t, _ := datasecure.NewTable(nil, nil, 0)
		if d.c.secure != nil {
			t = d.c.secure
		}
		t.SetToolKey(d.addr, k)
		d.sec = t
	}
}

// Device is the remote management of one device, its individual
// address, through the client's link: property values and the device
// descriptor. Requests are sent one at a time. Close it to end its
// transport connection.
type Device struct {
	c         *Client
	addr      knx.IndividualAddress
	connected bool
	sec       *datasecure.Table // with the device's tool key: secured

	in     chan *cemi.LData
	lock   chan struct{} // one request at a time
	open   bool          // the transport connection is open
	send   uint8         // next own sequence number
	recv   uint8         // next sequence number expected from the device
	last   time.Time
	synced bool
}

// Device returns the remote management of the device at addr. A second
// Device for the same address replaces the first.
func (c *Client) Device(addr knx.IndividualAddress, opts ...DeviceOption) *Device {
	d := &Device{c: c, addr: addr, in: make(chan *cemi.LData, 32), lock: make(chan struct{}, 1)}
	if c.secure != nil {
		if _, ok := c.secure.ToolKey(addr); ok {
			d.sec = c.secure
		}
	}
	for _, o := range opts {
		o(d)
	}
	c.mu.Lock()
	if c.devices == nil {
		c.devices = map[knx.IndividualAddress]*Device{}
	}
	c.devices[addr] = d
	c.mu.Unlock()
	return d
}

// Address returns the device's individual address.
func (d *Device) Address() knx.IndividualAddress { return d.addr }

// Secured reports whether the access is secured with the tool key.
func (d *Device) Secured() bool { return d.sec != nil }

// Close ends the transport connection (T_Disconnect) and releases the
// device.
func (d *Device) Close() error {
	d.c.mu.Lock()
	if d.c.devices[d.addr] == d {
		delete(d.c.devices, d.addr)
	}
	d.c.mu.Unlock()
	d.lock <- struct{}{}
	defer func() { <-d.lock }()
	if !d.open {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d.drain(ctx)
	d.open = false
	return d.transmit(ctx, apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TDisconnect}}.Bytes())
}

// PropertyRead reads count elements (1..15) of property pid of the
// interface object at index object from element start (1-based; start 0
// reads the number of elements).
func (d *Device) PropertyRead(ctx context.Context, object, pid uint8, start uint16, count uint8) ([]byte, error) {
	p := mgmt.Property{Object: object, PID: pid, Start: start, Count: count}
	return d.property(ctx, p, apdu.PropertyValueReadService)
}

// PropertyElements returns the number of elements of a property.
func (d *Device) PropertyElements(ctx context.Context, object, pid uint8) (int, error) {
	b, err := d.PropertyRead(ctx, object, pid, 0, 1)
	if err != nil {
		return 0, err
	}
	if len(b) != 2 {
		return 0, fmt.Errorf("%w: client: element count of %d octets", knx.ErrMalformed, len(b))
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

// PropertyWrite writes count elements of a property from element start
// and returns the value the device answers with (the elements after the
// write).
func (d *Device) PropertyWrite(ctx context.Context, object, pid uint8, start uint16, count uint8, data []byte) ([]byte, error) {
	p := mgmt.Property{Object: object, PID: pid, Start: start, Count: count, Data: data}
	return d.property(ctx, p, apdu.PropertyValueWriteService)
}

func (d *Device) property(ctx context.Context, p mgmt.Property, svc apdu.APCI) ([]byte, error) {
	if p.Count == 0 || p.Count > 15 || p.Start > 0x0FFF {
		return nil, fmt.Errorf("%w: client: property elements %d from %d", knx.ErrInvalidValue, p.Count, p.Start)
	}
	var out []byte
	err := d.request(ctx, func(tpci apdu.TPCI) []byte { return p.TPDU(tpci, svc) }, func(t apdu.TPDU) bool {
		if t.APCI != apdu.PropertyValueResponseService {
			return false
		}
		r, err := mgmt.ParseProperty(t)
		if err != nil || r.Object != p.Object || r.PID != p.PID || r.Start != p.Start {
			return false
		}
		if r.Count == 0 {
			out = nil
		} else {
			out = r.Data
			if out == nil {
				out = []byte{}
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, &mgmt.PropertyError{Device: d.addr, Object: p.Object, PID: p.PID}
	}
	return out, nil
}

// DescriptorRead reads the device descriptor type 0 (mask version).
func (d *Device) DescriptorRead(ctx context.Context) (uint16, error) {
	var v uint16
	refused := false
	err := d.request(ctx, mgmt.DescriptorTPDU, func(t apdu.TPDU) bool {
		if t.APCI != apdu.DeviceDescriptorResponseService {
			return false
		}
		if t.Short != 0 || len(t.Data) != 2 {
			refused = true
		} else {
			v = binary.BigEndian.Uint16(t.Data)
		}
		return true
	})
	if err == nil && refused {
		err = fmt.Errorf("%w: client: %s refused the device descriptor", knx.ErrRejected, d.addr)
	}
	return v, err
}

// request sends a request and waits for the answer accept takes.
func (d *Device) request(ctx context.Context, build func(apdu.TPCI) []byte, accept func(apdu.TPDU) bool) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	select {
	case d.lock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-d.lock }()
	d.drain(ctx)
	if d.connected && d.open && time.Since(d.last) > idleReconnect {
		d.open = false
	}
	if d.connected && !d.open {
		if err := d.transmit(ctx, apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TConnect}}.Bytes()); err != nil {
			return err
		}
		d.open, d.send, d.recv, d.last = true, 0, 0, time.Now()
	}
	if d.sec != nil && !d.synced {
		var challenge [6]byte
		err := d.exchange(ctx, func(tpci apdu.TPCI) (*cemi.LData, error) {
			f, c, err := d.sec.SyncRequest(d.code(), d.c.ownAddress(), d.addr, tpci.Octet())
			challenge = c
			return f, err
		}, func(f *cemi.LData) bool {
			if !datasecure.IsSecure(f) || len(f.TPDU) < 3 || datasecure.ParseSCF(f.TPDU[2]).Service != datasecure.SSyncRes {
				return false
			}
			return d.sec.OpenSyncResponse(f, challenge) == nil
		})
		if err != nil {
			return fmt.Errorf("client: S-A_Sync with %s: %w", d.addr, err)
		}
		d.synced = true
	}
	return d.exchange(ctx, func(tpci apdu.TPCI) (*cemi.LData, error) {
		f := cemi.NewIndividualFrame(d.code(), d.c.ownAddress(), d.addr, knx.PrioritySystem, build(tpci))
		if d.sec != nil {
			return d.sec.SealToolRequest(f)
		}
		return f, nil
	}, func(f *cemi.LData) bool {
		if d.sec != nil {
			if datasecure.IsSecure(f) && len(f.TPDU) > 2 && datasecure.ParseSCF(f.TPDU[2]).Service != datasecure.SData {
				return false
			}
			p, err := d.sec.OpenToolResponse(f)
			if err != nil {
				d.c.logger.Debugf("client: answer of %s: %v", d.addr, err)
				return false
			}
			f = p
		}
		t, err := apdu.Parse(f.TPDU)
		return err == nil && accept(t)
	})
}

// exchange sends a data PDU (repeated until acknowledged in a
// connection) and waits for the data PDU accept takes, acknowledging the
// device's data PDUs.
func (d *Device) exchange(ctx context.Context, build func(apdu.TPCI) (*cemi.LData, error), accept func(*cemi.LData) bool) error {
	tpci := apdu.TPCI{Kind: apdu.TData}
	if d.connected {
		tpci = apdu.TPCI{Kind: apdu.TDataConnected, Seq: d.send}
	}
	f, err := build(tpci)
	if err != nil {
		return err
	}
	if err := d.c.link.Send(ctx, f); err != nil {
		return err
	}
	acked, answered, reps := !d.connected, false, 0
	timer := time.NewTimer(ackTimeout)
	defer timer.Stop()
	for !acked || !answered {
		select {
		case <-ctx.Done():
			if d.connected {
				d.open = false
			}
			return fmt.Errorf("%w: client: no answer from %s", knx.ErrTimeout, d.addr)
		case <-timer.C:
			if acked {
				timer.Reset(ackTimeout)
				continue
			}
			if reps++; reps > maxRepetitions {
				d.open = false
				return fmt.Errorf("%w: client: %s did not acknowledge", knx.ErrTimeout, d.addr)
			}
			if err := d.c.link.Send(ctx, f); err != nil {
				return err
			}
			timer.Reset(ackTimeout)
		case in := <-d.in:
			t, err := apdu.Parse(in.TPDU)
			if err != nil {
				continue
			}
			if !d.connected {
				if t.TPCI.Kind == apdu.TData && accept(in) {
					answered = true
				}
				continue
			}
			d.last = time.Now()
			switch t.TPCI.Kind {
			case apdu.TAck:
				if t.TPCI.Seq == d.send && !acked {
					acked = true
					d.send = (d.send + 1) & 0x0F
				}
			case apdu.TNak:
				if t.TPCI.Seq == d.send && !acked {
					if err := d.c.link.Send(ctx, f); err != nil {
						return err
					}
				}
			case apdu.TDisconnect:
				d.open = false
				return fmt.Errorf("%w: client: %s closed the connection", knx.ErrConnectionLost, d.addr)
			case apdu.TDataConnected:
				switch t.TPCI.Seq {
				case d.recv:
					d.recv = (d.recv + 1) & 0x0F
					if err := d.ack(ctx, t.TPCI.Seq); err != nil {
						return err
					}
					if accept(in) {
						answered = true
					}
				case (d.recv - 1) & 0x0F:
					// A repetition: our acknowledgement was lost.
					if err := d.ack(ctx, t.TPCI.Seq); err != nil {
						return err
					}
				}
			default:
			}
		}
	}
	return nil
}

func (d *Device) ack(ctx context.Context, seq uint8) error {
	return d.transmit(ctx, apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TAck, Seq: seq}}.Bytes())
}

// transmit sends a TPDU to the device as it is.
func (d *Device) transmit(ctx context.Context, tpdu []byte) error {
	return d.c.link.Send(ctx, cemi.NewIndividualFrame(d.code(), d.c.ownAddress(), d.addr, knx.PrioritySystem, tpdu))
}

func (d *Device) code() cemi.MessageCode {
	if _, routed := d.c.link.(*routing.Conn); routed {
		return cemi.LDataInd
	}
	return cemi.LDataReq
}

// drain drops the frames that arrived after an earlier request ended; a
// repeated data PDU of the connection (the device missed our
// acknowledgement) is acknowledged again.
func (d *Device) drain(ctx context.Context) {
	for {
		select {
		case in := <-d.in:
			if t, err := apdu.Parse(in.TPDU); err == nil && d.open && t.TPCI.Kind == apdu.TDataConnected && t.TPCI.Seq == (d.recv-1)&0x0F {
				_ = d.ack(ctx, t.TPCI.Seq)
			}
		default:
			return
		}
	}
}

// deliverDevice hands a frame from a managed device to its Device; false
// when no Device manages the source.
func (c *Client) deliverDevice(ld *cemi.LData) bool {
	c.mu.Lock()
	d := c.devices[ld.Source]
	c.mu.Unlock()
	if d == nil {
		return false
	}
	if own := c.ownAddress(); own != 0 && knx.IndividualAddress(ld.Destination) != own {
		return true
	}
	select {
	case d.in <- ld:
	default:
	}
	return true
}
