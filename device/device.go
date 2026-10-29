// SPDX-License-Identifier: MIT

// Package device models virtual KNX devices: an individual address and
// group objects (communication objects) with their datapoint type, group
// addresses, communication flags and current value. A [Device] reacts to
// group telegrams as a KNX device's application layer does: it stores
// written values, answers reads and takes over responses, according to
// the flags.
//
// This is the application layer of a device only. It does not emulate a
// KNX TP device: no physical layer, no transport connections, no
// management (memory, properties, programming).
package device

import (
	"fmt"
	"strings"
	"sync"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/dpt"
)

// Flags are the communication flags of a group object.
type Flags uint8

// Communication flags.
const (
	// FlagCommunication (C) links the object to the bus at all.
	FlagCommunication Flags = 1 << iota
	// FlagRead (R) answers A_GroupValue_Read with the object's value.
	FlagRead
	// FlagWrite (W) accepts A_GroupValue_Write.
	FlagWrite
	// FlagTransmit (T) sends the value when the application changes it.
	FlagTransmit
	// FlagUpdate (U) takes over the value of A_GroupValue_Response.
	FlagUpdate
	// FlagReadOnInit (I) reads the value from the bus on start.
	FlagReadOnInit
)

// ParseFlags parses flag letters, such as "CRWTU".
func ParseFlags(s string) (Flags, error) {
	var f Flags
	for _, c := range strings.ToUpper(s) {
		switch c {
		case 'C':
			f |= FlagCommunication
		case 'R':
			f |= FlagRead
		case 'W':
			f |= FlagWrite
		case 'T':
			f |= FlagTransmit
		case 'U':
			f |= FlagUpdate
		case 'I':
			f |= FlagReadOnInit
		default:
			return 0, fmt.Errorf("%w: flag %q (C, R, W, T, U, I)", knx.ErrInvalidOption, c)
		}
	}
	return f, nil
}

// String returns the flag letters, such as "CRWT".
func (f Flags) String() string {
	var sb strings.Builder
	for i, c := range "CRWTUI" {
		if f&(1<<i) != 0 {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// GroupObject is a communication object.
type GroupObject struct {
	Name string
	Type *dpt.Type
	// Addresses are the associated group addresses; the first is the
	// sending address, used for transmissions and read responses.
	Addresses []knx.GroupAddress
	Flags     Flags

	mu    sync.Mutex
	value []byte
	set   bool
}

// NewGroupObject returns a group object of datapoint type id ("9.001")
// with flags ("CRWTU") and group addresses ("1/2/3"), the first being
// the sending address.
func NewGroupObject(name, id, flags string, addresses ...string) (*GroupObject, error) {
	t, err := dpt.Lookup(id)
	if err != nil {
		return nil, err
	}
	f, err := ParseFlags(flags)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%w: group object %q has no group address", knx.ErrInvalidOption, name)
	}
	o := &GroupObject{Name: name, Type: t, Flags: f}
	for _, a := range addresses {
		g, err := knx.ParseGroupAddress(a)
		if err != nil {
			return nil, err
		}
		o.Addresses = append(o.Addresses, g)
	}
	return o, nil
}

// SendingAddress returns the first group address.
func (o *GroupObject) SendingAddress() knx.GroupAddress { return o.Addresses[0] }

// Has reports whether g is one of the object's addresses.
func (o *GroupObject) Has(g knx.GroupAddress) bool {
	for _, a := range o.Addresses {
		if a == g {
			return true
		}
	}
	return false
}

// Raw returns the encoded value and whether one was set.
func (o *GroupObject) Raw() ([]byte, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]byte(nil), o.value...), o.set
}

// Value returns the decoded value; ok is false while none was set.
func (o *GroupObject) Value() (v any, ok bool, err error) {
	raw, ok := o.Raw()
	if !ok {
		return nil, false, nil
	}
	v, err = o.Type.Decode(raw)
	return v, true, err
}

// Set stores v (encoded with the object's type). It does not transmit;
// see [Device.Transmit].
func (o *GroupObject) Set(v any) error {
	raw, err := o.Type.Encode(v)
	if err != nil {
		return err
	}
	return o.SetRaw(raw)
}

// SetRaw stores an encoded value, checked for the size of the type.
func (o *GroupObject) SetRaw(raw []byte) error {
	if _, err := o.Type.Decode(raw); err != nil {
		return err
	}
	o.mu.Lock()
	o.value, o.set = append([]byte(nil), raw...), true
	o.mu.Unlock()
	return nil
}

// groupValue returns the stored value as A_GroupValue data.
func (o *GroupObject) groupValue() (apdu.GroupValue, bool) {
	raw, ok := o.Raw()
	if !ok {
		return apdu.GroupValue{}, false
	}
	return apdu.GroupValue{Data: raw, Small: o.Type.Small()}, true
}

// Event is a value change of a group object caused by a telegram.
type Event struct {
	Object *GroupObject
	// Service is GroupValueWriteService or GroupValueResponseService.
	Service apdu.APCI
	Source  knx.IndividualAddress
	Group   knx.GroupAddress
	Value   any
	Raw     []byte
}

// Device is a virtual device: an individual address and group objects.
type Device struct {
	Address knx.IndividualAddress
	Name    string

	mu      sync.Mutex
	objects []*GroupObject
	// onChange is called after a telegram changed an object.
	onChange func(Event)
}

// New returns a device with an individual address.
func New(name string, addr knx.IndividualAddress) *Device {
	return &Device{Name: name, Address: addr}
}

// Add adds group objects.
func (d *Device) Add(objs ...*GroupObject) *Device {
	d.mu.Lock()
	d.objects = append(d.objects, objs...)
	d.mu.Unlock()
	return d
}

// Objects returns the group objects.
func (d *Device) Objects() []*GroupObject {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*GroupObject(nil), d.objects...)
}

// Object returns the group object of that name.
func (d *Device) Object(name string) (*GroupObject, bool) {
	for _, o := range d.Objects() {
		if o.Name == name {
			return o, true
		}
	}
	return nil, false
}

// OnChange sets the handler called, synchronously, after a telegram
// changed a group object. It must not block.
func (d *Device) OnChange(f func(Event)) {
	d.mu.Lock()
	d.onChange = f
	d.mu.Unlock()
}

// Handle processes a group telegram (an L_Data frame to a group address)
// and returns the frames the device sends in reaction: at most one
// A_GroupValue_Response per read, from the first object with the C and R
// flags and a value. Frames to individual addresses, from the device
// itself, and services other than group values are ignored.
func (d *Device) Handle(f *cemi.LData) []*cemi.LData {
	g, ok := f.Group()
	if !ok || f.Source == d.Address {
		return nil
	}
	svc, v, err := apdu.ParseGroupValue(f.TPDU)
	if err != nil {
		return nil
	}
	d.mu.Lock()
	objs := append([]*GroupObject(nil), d.objects...)
	cb := d.onChange
	d.mu.Unlock()

	var out []*cemi.LData
	for _, o := range objs {
		if o.Flags&FlagCommunication == 0 || !o.Has(g) {
			continue
		}
		switch svc {
		case apdu.GroupValueReadService:
			if o.Flags&FlagRead == 0 || len(out) > 0 {
				continue
			}
			if gv, ok := o.groupValue(); ok {
				tpdu, err := apdu.GroupValueResponse(gv)
				if err == nil {
					out = append(out, cemi.NewGroupFrame(cemi.LDataInd, d.Address, g, f.Priority(), tpdu))
				}
			}
		case apdu.GroupValueWriteService, apdu.GroupValueResponseService:
			need := FlagWrite
			if svc == apdu.GroupValueResponseService {
				need = FlagUpdate
			}
			if o.Flags&need == 0 {
				continue
			}
			raw := v.Data
			if o.Type.Small() != v.Small {
				continue // size mismatch: not this object's type
			}
			if err := o.SetRaw(raw); err != nil {
				continue
			}
			if cb != nil {
				val, _ := o.Type.Decode(raw)
				cb(Event{Object: o, Service: svc, Source: f.Source, Group: g, Value: val, Raw: append([]byte(nil), raw...)})
			}
		default:
		}
	}
	return out
}

// Transmit sets the value of a group object and returns the
// A_GroupValue_Write telegram to its sending address the device sends,
// if the object has the C and T flags (nil otherwise).
func (d *Device) Transmit(o *GroupObject, v any) (*cemi.LData, error) {
	if err := o.Set(v); err != nil {
		return nil, err
	}
	if o.Flags&(FlagCommunication|FlagTransmit) != FlagCommunication|FlagTransmit {
		return nil, nil
	}
	gv, _ := o.groupValue()
	tpdu, err := apdu.GroupValueWrite(gv)
	if err != nil {
		return nil, err
	}
	return cemi.NewGroupFrame(cemi.LDataInd, d.Address, o.SendingAddress(), knx.PriorityLow, tpdu), nil
}
