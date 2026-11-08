// SPDX-License-Identifier: MIT

package capture

import (
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
)

// Exchange is one request of a management client to a device on a TP1
// line, with the link-layer repetitions of that request and the
// device's frames that follow, up to the client's next request.
type Exchange struct {
	Device knx.IndividualAddress
	// Request is the first transmission; Repeats are the frames with the
	// repeat flag that repeat it octet for octet.
	Request *cemi.LData
	Time    time.Time
	Repeats int
	// Answers are the device's frames to the client, in order, with
	// their time stamps.
	Answers []*cemi.LData
	Times   []time.Time
}

// Exchanges collects the point-to-point frames between client and the
// devices it addresses, as exchanges in capture order. Group frames,
// frames between other devices and frames from client to client are
// skipped: the line scan of knx-datasets addressed 1.1.102, the address
// the scanning tool used itself, and the installation's own device with
// that address answered; the two cannot be told apart by address.
func Exchanges(frames []TPFrame, client knx.IndividualAddress) []Exchange {
	var (
		out  []Exchange
		last = map[knx.IndividualAddress]int{} // device: index of its latest exchange
	)
	for _, fr := range frames {
		ld, err := cemi.ParseTP1(fr.Data)
		if err != nil || ld.IsGroup() {
			continue
		}
		dst := knx.IndividualAddress(ld.Destination)
		switch {
		case ld.Source == client && dst == client:
		case ld.Source == client:
			if i, ok := last[dst]; ok && ld.Repeat() && len(out[i].Answers) == 0 && sameFrame(out[i].Request, ld) {
				out[i].Repeats++
				continue
			}
			last[dst] = len(out)
			first := ld.Clone()
			first.Ctrl1 |= cemi.Ctrl1NoRepeat
			out = append(out, Exchange{Device: dst, Request: first, Time: fr.Time})
		case dst == client:
			if i, ok := last[ld.Source]; ok {
				out[i].Answers = append(out[i].Answers, ld)
				out[i].Times = append(out[i].Times, fr.Time)
			}
		}
	}
	return out
}

func sameFrame(a, b *cemi.LData) bool {
	return a.Source == b.Source && a.Destination == b.Destination && a.Ctrl2 == b.Ctrl2 &&
		a.Priority() == b.Priority() && string(a.TPDU) == string(b.TPDU)
}
