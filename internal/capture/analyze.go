// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/knxnetip"
)

// Stats are the counts go-knx derives from one capture: what decodes,
// what encodes again to the recorded octets, and the services seen.
type Stats struct {
	Frames int            `json:"frames"`
	Other  map[string]int `json:"other,omitempty"`
	TP     *TPStats       `json:"tp,omitempty"`
	IP     *IPStats       `json:"knxnetip,omitempty"`
}

// TPStats are the counts of the TP1 frames.
type TPStats struct {
	Frames   int            `json:"frames"`
	Decoded  int            `json:"decoded"` // cemi.ParseTP1 accepts the frame (check octet included)
	Rejected map[string]int `json:"rejected,omitempty"`
	// Reencoded counts the decoded frames cemi.TP1Frame encodes again to
	// the recorded octets; ReencodeDiffs the others, by control field.
	Reencoded     int            `json:"reencoded_byte_exact"`
	ReencodeDiffs map[string]int `json:"reencode_differences,omitempty"`
	// CEMI counts the frames whose L_Data.ind encodes and decodes again
	// to the same frame.
	CEMI       int            `json:"cemi_round_trip"`
	Repeated   int            `json:"repeated"`
	Group      int            `json:"group"`
	Individual int            `json:"individual"`
	Priority   map[string]int `json:"priority"`
	HopCount   map[string]int `json:"hop_count"`
	TPDU       TPDUStats      `json:"tpdu"`
}

// TPDUStats are the counts of the transport and application layer.
type TPDUStats struct {
	Decoded   int            `json:"decoded"`
	Rejected  map[string]int `json:"rejected,omitempty"`
	Reencoded int            `json:"reencoded_byte_exact"`
	// Services counts the control PDUs by TPCI (T_Connect, T_ACK...) and
	// the data PDUs by application service.
	Services map[string]int `json:"services"`
}

// IPStats are the counts of the KNXnet/IP frames.
type IPStats struct {
	UDPDatagrams int `json:"udp_datagrams"`
	// MultiFrameDatagrams are UDP datagrams holding more than one
	// KNXnet/IP frame; Trailing those with octets after the last frame.
	MultiFrameDatagrams int `json:"multi_frame_datagrams,omitempty"`
	Trailing            int `json:"trailing_octets_datagrams,omitempty"`
	TCPFrames           int `json:"tcp_frames"`
	TCPRest             int `json:"tcp_rest_octets,omitempty"`
	TCPGaps             int `json:"tcp_gaps,omitempty"`
	Frames              int `json:"frames"`
	Decoded             int `json:"decoded"`
	// Rejected counts the frames knxnetip.Parse refuses, by service and
	// error class.
	Rejected      map[string]int `json:"rejected,omitempty"`
	Reencoded     int            `json:"reencoded_byte_exact"`
	ReencodeDiffs map[string]int `json:"reencode_differences,omitempty"`
	Services      map[string]int `json:"services"`
	// ServiceCodes counts the service type codes of every frame, decoded
	// or not ("0x0530"), for comparison with Wireshark.
	ServiceCodes map[string]int `json:"service_codes"`
	// CEMI counts the cEMI frames of tunnelling, routing and device
	// management; CEMIDecoded those cemi.Parse accepts and CEMIReencoded
	// those that encode again to the recorded octets.
	CEMI          int            `json:"cemi"`
	CEMIDecoded   int            `json:"cemi_decoded"`
	CEMIRejected  map[string]int `json:"cemi_rejected,omitempty"`
	CEMIReencoded int            `json:"cemi_reencoded_byte_exact"`
	CEMICodes     map[string]int `json:"cemi_codes,omitempty"`
	// CEMICodeOctets counts the message code octets of every cEMI frame,
	// decoded or not ("0x29"), for comparison with Wireshark.
	CEMICodeOctets map[string]int `json:"cemi_code_octets,omitempty"`
	TPDU           TPDUStats      `json:"tpdu"`
}

// Analyze decodes everything in f with go-knx.
func Analyze(f *File) Stats {
	st := Stats{Frames: f.Frames}
	if len(f.Other) > 0 {
		st.Other = f.Other
	}
	if len(f.TP) > 0 {
		st.TP = analyzeTP(f.TP)
	}
	if len(f.IP) > 0 {
		st.IP = analyzeIP(f)
	}
	return st
}

func analyzeTP(frames []TPFrame) *TPStats {
	s := &TPStats{Rejected: map[string]int{}, ReencodeDiffs: map[string]int{}, Priority: map[string]int{}, HopCount: map[string]int{},
		TPDU: newTPDUStats()}
	for _, fr := range frames {
		s.Frames++
		ld, err := cemi.ParseTP1(fr.Data)
		if err != nil {
			s.Rejected[ErrorClass(err)]++
			continue
		}
		s.Decoded++
		if b, err := cemi.TP1Frame(ld); err == nil && bytes.Equal(b, fr.Data) {
			s.Reencoded++
		} else {
			s.ReencodeDiffs[fmt.Sprintf("control 0x%02X", fr.Data[0])]++
		}
		if b, err := cemi.Marshal(ld); err == nil {
			if g, err := cemi.Parse(b); err == nil && sameLData(g, ld) {
				s.CEMI++
			}
		}
		if ld.Repeat() {
			s.Repeated++
		}
		if ld.IsGroup() {
			s.Group++
		} else {
			s.Individual++
		}
		s.Priority[ld.Priority().String()]++
		s.HopCount[fmt.Sprint(ld.HopCount())]++
		s.TPDU.add(ld.TPDU)
	}
	s.TPDU.trim()
	if len(s.Rejected) == 0 {
		s.Rejected = nil
	}
	if len(s.ReencodeDiffs) == 0 {
		s.ReencodeDiffs = nil
	}
	return s
}

func sameLData(g cemi.Frame, want *cemi.LData) bool {
	ld, ok := g.(*cemi.LData)
	return ok && ld.MsgCode == want.MsgCode && ld.Ctrl1 == want.Ctrl1 && ld.Ctrl2 == want.Ctrl2 &&
		ld.Source == want.Source && ld.Destination == want.Destination && bytes.Equal(ld.TPDU, want.TPDU)
}

func newTPDUStats() TPDUStats {
	return TPDUStats{Rejected: map[string]int{}, Services: map[string]int{}}
}

func (s *TPDUStats) add(b []byte) {
	t, err := apdu.Parse(b)
	if err != nil {
		s.Rejected[ErrorClass(err)]++
		return
	}
	s.Decoded++
	if bytes.Equal(t.Bytes(), b) {
		s.Reencoded++
	}
	s.Services[ServiceName(t)]++
}

func (s *TPDUStats) trim() {
	if len(s.Rejected) == 0 {
		s.Rejected = nil
	}
}

// ServiceName names a TPDU: its TPCI for a control PDU, else its
// application service.
func ServiceName(t apdu.TPDU) string {
	if t.TPCI.IsControl() {
		return t.TPCI.Kind.String()
	}
	return t.APCI.String()
}

// ErrorClass reduces an error to its sentinel, for counting.
func ErrorClass(err error) string {
	for _, e := range []error{knx.ErrMalformed, knx.ErrUnsupported, knx.ErrInvalidValue} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return err.Error()
}

// Frames cuts a UDP datagram into the KNXnet/IP frames it holds (normally
// one); rest is what follows the last whole frame.
func Frames(b []byte) (frames [][]byte, rest []byte) {
	for len(b) >= knxnetip.HeaderLen && isKNXnetIP(b) {
		n := int(binary.BigEndian.Uint16(b[4:]))
		if n < knxnetip.HeaderLen || n > len(b) {
			break
		}
		frames = append(frames, b[:n])
		b = b[n:]
	}
	return frames, b
}

// CEMIOf returns the cEMI frame a KNXnet/IP message carries, if any.
func CEMIOf(m knxnetip.Message) []byte {
	switch m := m.(type) {
	case *knxnetip.TunnellingRequest:
		return m.CEMI
	case *knxnetip.DeviceConfigurationRequest:
		return m.CEMI
	case *knxnetip.RoutingIndication:
		return m.CEMI
	}
	return nil
}

func analyzeIP(f *File) *IPStats {
	s := &IPStats{Rejected: map[string]int{}, ReencodeDiffs: map[string]int{}, Services: map[string]int{}, ServiceCodes: map[string]int{},
		CEMIRejected: map[string]int{}, CEMICodes: map[string]int{}, CEMICodeOctets: map[string]int{}, TPDU: newTPDUStats(),
		TCPRest: f.TCPRest, TCPGaps: f.TCPGaps}
	for _, d := range f.IP {
		frames := [][]byte{d.Data}
		if d.Transport == UDP {
			s.UDPDatagrams++
			var rest []byte
			frames, rest = Frames(d.Data)
			if len(frames) > 1 {
				s.MultiFrameDatagrams++
			}
			if len(rest) > 0 {
				s.Trailing++
				if len(frames) == 0 {
					frames = [][]byte{d.Data}
				}
			}
		} else {
			s.TCPFrames++
		}
		for _, b := range frames {
			s.frame(b)
		}
	}
	if len(s.Rejected) == 0 {
		s.Rejected = nil
	}
	if len(s.ReencodeDiffs) == 0 {
		s.ReencodeDiffs = nil
	}
	if len(s.CEMIRejected) == 0 {
		s.CEMIRejected = nil
	}
	if len(s.CEMICodes) == 0 {
		s.CEMICodes = nil
	}
	if len(s.CEMICodeOctets) == 0 {
		s.CEMICodeOctets = nil
	}
	s.TPDU.trim()
	return s
}

func (s *IPStats) frame(b []byte) {
	s.Frames++
	svc := "short"
	if len(b) >= 4 {
		code := binary.BigEndian.Uint16(b[2:])
		svc = knxnetip.ServiceType(code).String()
		s.ServiceCodes[fmt.Sprintf("0x%04X", code)]++
	}
	m, err := knxnetip.Parse(b)
	if err != nil {
		s.Rejected[svc+": "+ErrorClass(err)]++
		return
	}
	s.Decoded++
	s.Services[m.Service().String()]++
	if e, err := knxnetip.Marshal(m); err == nil && bytes.Equal(e, b) {
		s.Reencoded++
	} else {
		s.ReencodeDiffs[m.Service().String()]++
	}
	c := CEMIOf(m)
	if c == nil {
		return
	}
	s.CEMI++
	s.CEMICodeOctets[fmt.Sprintf("0x%02X", c[0])]++
	fr, err := cemi.Parse(c)
	if err != nil {
		s.CEMIRejected[fmt.Sprintf("0x%02X: %s", c[0], ErrorClass(err))]++
		return
	}
	s.CEMIDecoded++
	s.CEMICodes[fr.Code().String()]++
	if e, err := cemi.Marshal(fr); err == nil && bytes.Equal(e, c) {
		s.CEMIReencoded++
	}
	if ld, ok := fr.(*cemi.LData); ok {
		s.TPDU.add(ld.TPDU)
	}
}
