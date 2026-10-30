// SPDX-License-Identifier: MIT

package datasecure

import (
	"crypto/rand"
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
	mu       sync.Mutex
	keys     map[knx.GroupAddress]Key
	senders  map[knx.IndividualAddress]uint64
	seq      uint64
	toolKeys map[knx.IndividualAddress]Key
	// tools holds the last valid tool access sequence number of each
	// peer: of the tools that access this table's devices, and of the
	// devices this table accesses as a tool.
	tools map[knx.IndividualAddress]uint64
	// synced holds the sequence number of each sender's last answered
	// S-A_Sync_Req: its next tool access frame may reuse it once.
	synced map[knx.IndividualAddress]uint64
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
	t := &Table{keys: map[knx.GroupAddress]Key{}, senders: map[knx.IndividualAddress]uint64{}, seq: seq, toolKeys: map[knx.IndividualAddress]Key{}, tools: map[knx.IndividualAddress]uint64{}, synced: map[knx.IndividualAddress]uint64{}}
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

// SetToolKey sets the tool key of a device. A Table answers the
// S-A_Sync_Req addressed to its own device with that device's tool key
// (see Respond).
func (t *Table) SetToolKey(a knx.IndividualAddress, k Key) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.toolKeys[a] = k
}

// Respond answers an S-A_Sync_Req addressed to own, the device of this
// table: it returns the S-A_Sync_Res (message code code) with this
// table's next sending sequence number and the next sequence number it
// accepts from the requester. It returns nil, nil for frames that are not
// such a request. A request that fails authentication is refused with
// knx.ErrSecurity. The tool key authenticates the requester: any tool
// that has it may synchronise.
//
// A sender of a secured group (Calimero, for example) asks a receiver of
// the group, its "surrogate", for the sequence numbers before it sends;
// a tool synchronises before it accesses the device (see OpenTool).
func (t *Table) Respond(f *cemi.LData, own knx.IndividualAddress, code cemi.MessageCode) (*cemi.LData, error) {
	if len(f.TPDU) == 0 {
		return nil, nil
	}
	return t.RespondTPCI(f, own, code, f.TPDU[0]&0xFC)
}

// RespondTPCI is Respond with the TPCI octet of the response: in a
// transport connection the response is numbered with the responder's own
// sequence number.
func (t *Table) RespondTPCI(f *cemi.LData, own knx.IndividualAddress, code cemi.MessageCode, tpci byte) (*cemi.LData, error) {
	if f.IsGroup() || knx.IndividualAddress(f.Destination) != own || !IsSecure(f) || len(f.TPDU) < 3 || ParseSCF(f.TPDU[2]).Service != SSyncReq {
		return nil, nil
	}
	t.mu.Lock()
	key, ok := t.toolKeys[own]
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: datasecure: S-A_Sync_Req to %s without its tool key", knx.ErrSecurity, own)
	}
	req, err := OpenSyncRequest(key, f)
	if err != nil {
		return nil, err
	}
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	t.mu.Lock()
	last := t.tools[f.Source]
	remote := t.seq
	t.synced[f.Source] = req.Sequence
	t.mu.Unlock()
	return SyncResponse(key, code, own, f.Source, tpci, req.Challenge, random, remote, last+1)
}

// OpenTool verifies and decrypts an S-A_Data with tool access addressed
// to own, with own's tool key: its sequence number must be new. It
// returns nil, nil for frames that are not such a frame.
func (t *Table) OpenTool(f *cemi.LData, own knx.IndividualAddress) (*cemi.LData, error) {
	if f.IsGroup() || knx.IndividualAddress(f.Destination) != own || !IsSecure(f) || len(f.TPDU) < 3 {
		return nil, nil
	}
	scf := ParseSCF(f.TPDU[2])
	if !scf.ToolAccess || scf.Service != SData {
		return nil, nil
	}
	t.mu.Lock()
	key, ok := t.toolKeys[own]
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: datasecure: tool access to %s without its tool key", knx.ErrSecurity, own)
	}
	plain, seq, _, err := Open(key, f)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	last := t.tools[f.Source]
	// A new sequence number, or once the one of the sender's answered
	// S-A_Sync_Req (Calimero sends its first frame with it).
	s, pending := t.synced[f.Source]
	switch {
	case seq > last:
	case pending && seq == s:
	default:
		return nil, fmt.Errorf("%w: datasecure: sequence %d of %s not above %d", knx.ErrSecurity, seq, f.Source, last)
	}
	delete(t.synced, f.Source)
	if seq > last {
		t.tools[f.Source] = seq
	}
	return plain, nil
}

// SealTool secures a point to point frame from own with own's tool key
// (S-A_Data with tool access), with the next sending sequence number.
func (t *Table) SealTool(f *cemi.LData) (*cemi.LData, error) {
	t.mu.Lock()
	key, ok := t.toolKeys[f.Source]
	seq := t.seq
	if ok {
		t.seq++
	}
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: datasecure: no tool key of %s", knx.ErrSecurity, f.Source)
	}
	return Seal(key, f, seq, SCF{ToolAccess: true, Algorithm: AuthConf, Service: SData})
}

// ToolKey returns the tool key of a device.
func (t *Table) ToolKey(a knx.IndividualAddress) (Key, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k, ok := t.toolKeys[a]
	return k, ok
}

// SyncRequest returns an S-A_Sync_Req from src, a tool, to dst, a device
// whose tool key the table has, with the table's next sending sequence
// number, and the challenge to pass to OpenSyncResponse. tpci is the TPCI
// octet (0 connectionless). The serial number field is zero, as Calimero
// sends it.
func (t *Table) SyncRequest(code cemi.MessageCode, src, dst knx.IndividualAddress, tpci byte) (*cemi.LData, [6]byte, error) {
	var challenge [6]byte
	t.mu.Lock()
	key, ok := t.toolKeys[dst]
	seq := t.seq
	t.mu.Unlock()
	if !ok {
		return nil, challenge, fmt.Errorf("%w: datasecure: no tool key of %s", knx.ErrSecurity, dst)
	}
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, challenge, err
	}
	f, err := SyncRequest(key, code, src, dst, tpci, seq, [6]byte{}, challenge)
	return f, challenge, err
}

// OpenSyncResponse verifies a device's S-A_Sync_Res to the request with
// challenge and takes over its sequence numbers: the table sends with at
// least the one the device expects and accepts the device's from the one
// it announced.
func (t *Table) OpenSyncResponse(f *cemi.LData, challenge [6]byte) error {
	t.mu.Lock()
	key, ok := t.toolKeys[f.Source]
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: datasecure: no tool key of %s", knx.ErrSecurity, f.Source)
	}
	remote, local, err := OpenSyncResponse(key, f, challenge)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if local > t.seq {
		t.seq = local
	}
	if remote > 0 {
		t.tools[f.Source] = remote - 1
	} else {
		delete(t.tools, f.Source)
	}
	return nil
}

// SealToolRequest secures a point to point frame from a tool to a device
// with the device's tool key (S-A_Data with tool access), with the next
// sending sequence number.
func (t *Table) SealToolRequest(f *cemi.LData) (*cemi.LData, error) {
	dst := knx.IndividualAddress(f.Destination)
	t.mu.Lock()
	key, ok := t.toolKeys[dst]
	seq := t.seq
	if ok {
		t.seq++
	}
	t.mu.Unlock()
	if !ok || f.IsGroup() {
		return nil, fmt.Errorf("%w: datasecure: no tool key of %s", knx.ErrSecurity, dst)
	}
	return Seal(key, f, seq, SCF{ToolAccess: true, Algorithm: AuthConf, Service: SData})
}

// OpenToolResponse verifies and decrypts a device's S-A_Data with tool
// access to a tool, with the device's tool key: its sequence number must
// be new.
func (t *Table) OpenToolResponse(f *cemi.LData) (*cemi.LData, error) {
	if f.IsGroup() || !IsSecure(f) || len(f.TPDU) < 3 {
		return nil, fmt.Errorf("%w: datasecure: not a secured point to point frame", knx.ErrSecurity)
	}
	scf := ParseSCF(f.TPDU[2])
	if !scf.ToolAccess || scf.Service != SData {
		return nil, fmt.Errorf("%w: datasecure: frame of %s without tool access", knx.ErrSecurity, f.Source)
	}
	t.mu.Lock()
	key, ok := t.toolKeys[f.Source]
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: datasecure: no tool key of %s", knx.ErrSecurity, f.Source)
	}
	plain, seq, _, err := Open(key, f)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if last, ok := t.tools[f.Source]; ok && seq <= last {
		return nil, fmt.Errorf("%w: datasecure: sequence %d of %s not above %d", knx.ErrSecurity, seq, f.Source, last)
	}
	t.tools[f.Source] = seq
	return plain, nil
}
