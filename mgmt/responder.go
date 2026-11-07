// SPDX-License-Identifier: MIT

package mgmt

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/datasecure"
)

const (
	// connectionTimeout ends a transport connection without traffic.
	connectionTimeout = 6 * time.Second
	// ackTimeout is the transport layer's acknowledgement timeout: an
	// answer not acknowledged within it is repeated, at most
	// maxRepetitions times; then the connection is ended.
	ackTimeout     = 3 * time.Second
	maxRepetitions = 3
)

// Properties are the interface object properties a [Responder] serves,
// with objects addressed by their index in the interface object list.
type Properties interface {
	// ReadProperty returns count elements from element start (start 0:
	// the element count, two octets); ok false refuses the access.
	ReadProperty(object, pid uint8, start uint16, count uint8) (data []byte, ok bool)
	// WriteProperty writes count elements from element start; false
	// refuses the access.
	WriteProperty(object, pid uint8, start uint16, count uint8, data []byte) bool
}

// Describer describes properties, by PID or, with pid 0, by their index
// in the object. A [Responder] whose Properties implement it answers
// A_PropertyDescription_Read, which tools such as Calimero send before a
// property access to learn the datatype.
type Describer interface {
	DescribeProperty(object, pid, index uint8) (Description, bool)
}

// Responder answers remote device management addressed to one device:
// A_PropertyValue_Read and _Write, A_PropertyDescription_Read (with a
// [Describer]), A_DeviceDescriptor_Read (type 0),
// connectionless and in one transport connection at a time.
//
// With Security, which holds the device's tool key, management is
// secured: the responder answers S-A_Sync_Req and S-A_Data with tool
// access only, and its answers are secured with the tool key; plain
// requests are not answered.
//
// The transport layer acknowledges and checks sequence numbers. An answer
// in a transport connection that the peer refuses (T_NAK) or does not
// acknowledge within 3 s ([Responder.Repeat]) is repeated, at most three
// times; then the responder ends the connection.
type Responder struct {
	Address    knx.IndividualAddress
	Descriptor uint16 // device descriptor type 0
	Properties Properties
	Security   *datasecure.Table
	// Code is the message code of the answers; zero is L_Data.ind.
	Code cemi.MessageCode

	mu        sync.Mutex
	connected bool
	peer      knx.IndividualAddress
	recv      uint8 // next sequence number expected from the peer
	send      uint8 // sequence number of the next answer
	last      time.Time
	pending   *cemi.LData // the answer awaiting its T_Ack
	sent      time.Time   // when pending was last sent
	repeats   int         // repetitions of pending so far
}

// Handle processes a frame and returns the frames to send in answer, in
// order; nil for frames not addressed to the device.
func (r *Responder) Handle(f *cemi.LData) []*cemi.LData {
	if f.IsGroup() || knx.IndividualAddress(f.Destination) != r.Address || f.Source == r.Address {
		return nil
	}
	t, err := apdu.Parse(f.TPDU)
	if err != nil {
		return nil
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.connected && now.Sub(r.last) > connectionTimeout {
		r.connected, r.pending = false, nil
	}
	ours := r.connected && r.peer == f.Source
	switch t.TPCI.Kind {
	case apdu.TConnect:
		if r.connected && !ours {
			return []*cemi.LData{r.control(f.Source, apdu.TPCI{Kind: apdu.TDisconnect})}
		}
		r.connected, r.peer, r.recv, r.send, r.last, r.pending = true, f.Source, 0, 0, now, nil
	case apdu.TDisconnect:
		if ours {
			r.connected, r.pending = false, nil
		}
	case apdu.TAck:
		if ours && t.TPCI.Seq == r.send {
			r.send = (r.send + 1) & 0x0F
			r.last, r.pending = now, nil
		}
	case apdu.TDataConnected:
		if !ours {
			return []*cemi.LData{r.control(f.Source, apdu.TPCI{Kind: apdu.TDisconnect})}
		}
		r.last = now
		ack := r.control(f.Source, apdu.TPCI{Kind: apdu.TAck, Seq: t.TPCI.Seq})
		switch t.TPCI.Seq {
		case (r.recv - 1) & 0x0F: // a repetition: acknowledged again only
			return []*cemi.LData{ack}
		case r.recv:
		default:
			r.connected, r.pending = false, nil
			return []*cemi.LData{r.control(f.Source, apdu.TPCI{Kind: apdu.TDisconnect})}
		}
		r.recv = (r.recv + 1) & 0x0F
		out := []*cemi.LData{ack}
		if a := r.answer(f, apdu.TPCI{Kind: apdu.TDataConnected, Seq: r.send}); a != nil {
			out = append(out, a)
			r.pending, r.sent, r.repeats = a, now, 0
		}
		return out
	case apdu.TData:
		if a := r.answer(f, apdu.TPCI{Kind: apdu.TData}); a != nil {
			return []*cemi.LData{a}
		}
	case apdu.TNak:
		// The peer refuses the answer: repeat it now, within the limit.
		if ours && t.TPCI.Seq == r.send && r.pending != nil {
			r.last = now
			return r.repeat(now)
		}
	default:
		// Tagged group data.
	}
	return nil
}

// Repeat returns the frames due at now: the answer in a transport
// connection that the peer has not acknowledged within 3 s of sending it,
// repeated at most three times, and after the last repetition a
// T_Disconnect that ends the connection. Call it about once a second;
// nil when nothing is due. The peer misses an answer now and then
// (Calimero's transport layer does, when the answer closely follows the
// T_Ack); a repetition with the same sequence number recovers it.
func (r *Responder) Repeat(now time.Time) []*cemi.LData {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.connected || r.pending == nil || now.Sub(r.sent) < ackTimeout {
		return nil
	}
	r.last = now
	return r.repeat(now)
}

// repeat returns the pending answer again, or a T_Disconnect once it was
// repeated maxRepetitions times; r.mu is held.
func (r *Responder) repeat(now time.Time) []*cemi.LData {
	if r.repeats == maxRepetitions {
		r.connected, r.pending = false, nil
		return []*cemi.LData{r.control(r.peer, apdu.TPCI{Kind: apdu.TDisconnect})}
	}
	r.repeats++
	r.sent = now
	return []*cemi.LData{r.pending.Clone()}
}

func (r *Responder) code() cemi.MessageCode {
	if r.Code == 0 {
		return cemi.LDataInd
	}
	return r.Code
}

func (r *Responder) control(to knx.IndividualAddress, t apdu.TPCI) *cemi.LData {
	return cemi.NewIndividualFrame(r.code(), r.Address, to, knx.PrioritySystem, apdu.TPDU{TPCI: t}.Bytes())
}

// answer returns the answer to a data PDU, numbered with tpci.
func (r *Responder) answer(f *cemi.LData, tpci apdu.TPCI) *cemi.LData {
	if datasecure.IsSecure(f) != (r.Security != nil) {
		// Plain access to a secured device, or secured access to a device
		// without keys.
		return nil
	}
	if r.Security != nil {
		if len(f.TPDU) > 2 && datasecure.ParseSCF(f.TPDU[2]).Service == datasecure.SSyncReq {
			res, err := r.Security.RespondTPCI(f, r.Address, r.code(), tpci.Octet())
			if err != nil {
				return nil
			}
			return res
		}
		plain, err := r.Security.OpenTool(f, r.Address)
		if err != nil || plain == nil {
			return nil
		}
		f = plain
	}
	t, err := apdu.Parse(f.TPDU)
	if err != nil {
		return nil
	}
	tpdu := r.service(t, tpci)
	if tpdu == nil {
		return nil
	}
	out := cemi.NewIndividualFrame(r.code(), r.Address, f.Source, knx.PrioritySystem, tpdu)
	if r.Security != nil {
		if out, err = r.Security.SealTool(out); err != nil {
			return nil
		}
	}
	return out
}

// service returns the TPDU answering an application layer request; nil
// for services the responder does not answer.
func (r *Responder) service(t apdu.TPDU, tpci apdu.TPCI) []byte {
	switch t.APCI {
	case apdu.PropertyValueReadService, apdu.PropertyValueWriteService:
		p, err := ParseProperty(t)
		if err != nil || r.Properties == nil {
			return nil
		}
		ok := true
		if t.APCI == apdu.PropertyValueWriteService {
			ok = r.Properties.WriteProperty(p.Object, p.PID, p.Start, p.Count, p.Data)
		}
		var data []byte
		if ok {
			data, ok = r.Properties.ReadProperty(p.Object, p.PID, p.Start, p.Count)
		}
		res := Property{Object: p.Object, PID: p.PID, Start: p.Start}
		if ok {
			res.Count, res.Data = p.Count, data
		}
		return res.TPDU(tpci, apdu.PropertyValueResponseService)
	case apdu.PropertyDescriptionReadService:
		ds, ok := r.Properties.(Describer)
		if !ok || len(t.Data) != 3 {
			return nil
		}
		object, pid, index := t.Data[0], t.Data[1], t.Data[2]
		d, ok := ds.DescribeProperty(object, pid, index)
		if !ok {
			// A negative response: no type, no elements, no access.
			d = Description{PID: pid, Index: index}
		}
		d.Object = object
		return d.TPDU(tpci)
	case apdu.DeviceDescriptorReadService:
		if t.Short != 0 {
			// Descriptor types other than 0: the error response, type 63.
			return apdu.TPDU{TPCI: tpci, APCI: apdu.DeviceDescriptorResponseService, Short: 0x3F}.Bytes()
		}
		return apdu.TPDU{TPCI: tpci, APCI: apdu.DeviceDescriptorResponseService, Data: binary.BigEndian.AppendUint16(nil, r.Descriptor)}.Bytes()
	default:
		return nil
	}
}
