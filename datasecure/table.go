// SPDX-License-Identifier: MIT

package datasecure

import (
	"fmt"
	"sync"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
)

// sequenceEpoch is the origin of the first sending sequence number when
// none is stored: milliseconds since then always exceed what a device
// has seen before (xknx uses the same origin).
var sequenceEpoch = time.Date(2018, 1, 5, 0, 0, 0, 0, time.UTC)

// Table holds the security tables of a Data Secure endpoint: the group
// keys, the last valid sequence number of each known sender, and the
// own sending sequence number. It is safe for concurrent use.
type Table struct {
	mu      sync.Mutex
	keys    map[knx.GroupAddress]Key
	senders map[knx.IndividualAddress]uint64
	seq     uint64
}

// NewTable returns a table. senders maps each sender that may send to
// the secured groups to its last valid sequence number (0 if unknown).
// seq is the next sending sequence number; 0 starts at the milliseconds
// since 2018-01-05, which exceeds earlier runs.
func NewTable(keys map[knx.GroupAddress]Key, senders map[knx.IndividualAddress]uint64, seq uint64) (*Table, error) {
	if seq == 0 {
		seq = uint64(time.Since(sequenceEpoch).Milliseconds())
	}
	if seq > MaxSequence {
		return nil, fmt.Errorf("%w: datasecure: sequence %d exceeds 48 bits", knx.ErrInvalidValue, seq)
	}
	t := &Table{keys: map[knx.GroupAddress]Key{}, senders: map[knx.IndividualAddress]uint64{}, seq: seq}
	for g, k := range keys {
		t.keys[g] = k
	}
	for a, s := range senders {
		t.senders[a] = s
	}
	return t, nil
}

// Secured reports whether a group address has a key.
func (t *Table) Secured(g knx.GroupAddress) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.keys[g]
	return ok
}

// AddSender allows a sender with its last valid sequence number.
func (t *Table) AddSender(a knx.IndividualAddress, last uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.senders[a]; !ok || last > cur {
		t.senders[a] = last
	}
}

// Sequence returns the next sending sequence number. Persist it to
// continue after a restart.
func (t *Table) Sequence() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.seq
}

// Outgoing secures a group telegram to a secured group (S-A_Data with
// encryption) and returns other frames unchanged.
func (t *Table) Outgoing(f *cemi.LData) (*cemi.LData, error) {
	g, ok := f.Group()
	if !ok {
		return f, nil
	}
	t.mu.Lock()
	key, secured := t.keys[g]
	seq := t.seq
	if secured {
		if seq > MaxSequence {
			t.mu.Unlock()
			return nil, fmt.Errorf("%w: datasecure: sending sequence exhausted", knx.ErrSecurity)
		}
		t.seq++
	}
	t.mu.Unlock()
	if !secured {
		return f, nil
	}
	return Seal(key, f, seq, GroupData)
}

// Incoming opens a secured group telegram. A plain telegram to a secured
// group, a secured one from an unknown sender or with an old sequence
// number, and one that fails authentication are refused with
// knx.ErrSecurity. Frames to other groups pass unchanged.
func (t *Table) Incoming(f *cemi.LData) (*cemi.LData, error) {
	g, group := f.Group()
	if !IsSecure(f) {
		if group && t.Secured(g) {
			return nil, fmt.Errorf("%w: datasecure: plain telegram from %s to secured group %s", knx.ErrSecurity, f.Source, g)
		}
		return f, nil
	}
	if !group {
		return nil, fmt.Errorf("%w: datasecure: point to point security", knx.ErrUnsupported)
	}
	t.mu.Lock()
	key, ok := t.keys[g]
	_, known := t.senders[f.Source]
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: datasecure: no key for group %s", knx.ErrSecurity, g)
	}
	if !known {
		return nil, fmt.Errorf("%w: datasecure: unknown sender %s", knx.ErrSecurity, f.Source)
	}
	plain, seq, scf, err := Open(key, f)
	if err != nil {
		return nil, err
	}
	if scf.ToolAccess || scf.SystemBroadcast {
		return nil, fmt.Errorf("%w: datasecure: tool access or system broadcast to a group", knx.ErrSecurity)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if last := t.senders[f.Source]; seq <= last {
		return nil, fmt.Errorf("%w: datasecure: sequence %d of %s not above %d", knx.ErrSecurity, seq, f.Source, last)
	}
	t.senders[f.Source] = seq
	return plain, nil
}
