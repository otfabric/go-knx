// SPDX-License-Identifier: MIT

package datasecure

import (
	"crypto/subtle"
	"fmt"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/ccm"
)

// S-A_Sync: a sender asks a receiver (individually addressed, with the
// receiver's tool key) for the sequence numbers to use. The layout follows
// the open xknx S-A_Sync work (MIT) and its reproduction of the
// Application Layer Annex C worked examples:
//
//	S-A_Sync_Req: SeqNr_local(6) | KNX serial number(6, plain) | challenge(6, encrypted) | MAC(4)
//	              A = SCF | serial number, P = challenge, nonce = SeqNr_local
//	S-A_Sync_Res: challenge XOR random(6) | SeqNr_remote(6) | SeqNr_local(6) (encrypted) | MAC(4)
//	              A = SCF, P = the two sequence numbers, nonce = random
//
// In the response SeqNr_remote is the responder's next sending sequence
// number and SeqNr_local the next one it accepts from the requester.

// SyncRequestSCF and SyncResponseSCF are the SCFs of S-A_Sync with the
// tool key.
var (
	SyncRequestSCF  = SCF{ToolAccess: true, Algorithm: AuthConf, Service: SSyncReq}
	SyncResponseSCF = SCF{ToolAccess: true, Algorithm: AuthConf, Service: SSyncRes}
)

// syncLen is the length of a sync TPDU: secure APCI, SCF, six octet
// field, two six octet fields, MAC.
const syncLen = 2 + 1 + 6 + 12 + macLen

// sealCCM encrypts payload with nonce in place of the sequence number and
// returns the cipher and the 4-octet MAC.
func sealCCM(key Key, f *cemi.LData, tpci byte, nonce [6]byte, ad, payload []byte) (cipher, mac []byte) {
	scfLess := SCF{Algorithm: AuthConf}
	m := ccm.MAC(key[:], block0(f, tpci, nonce, payload, scfLess), ad, payload)
	s := ccm.XOR(key[:], ctr0(f, nonce), append(m[:macLen:macLen], payload...))
	return s[macLen:], s[:macLen]
}

func openCCM(key Key, f *cemi.LData, tpci byte, nonce [6]byte, ad, cipher, mac []byte) ([]byte, error) {
	s := ccm.XOR(key[:], ctr0(f, nonce), append(append([]byte(nil), mac...), cipher...))
	plain := s[macLen:]
	want := ccm.MAC(key[:], block0(f, tpci, nonce, plain, SCF{Algorithm: AuthConf}), ad, plain)
	if subtle.ConstantTimeCompare(s[:macLen], want[:macLen]) != 1 {
		return nil, fmt.Errorf("%w: datasecure: S-A_Sync authentication failed", knx.ErrSecurity)
	}
	return plain, nil
}

// syncFrame returns an individually addressed frame for a sync TPDU.
func syncFrame(code cemi.MessageCode, src, dst knx.IndividualAddress, tpdu []byte) *cemi.LData {
	f := cemi.NewIndividualFrame(code, src, dst, knx.PrioritySystem, tpdu)
	return f
}

// SyncRequest returns an S-A_Sync_Req from src to dst: seq is the
// requester's sequence number, challenge six random octets, key the tool
// key of dst. tpci is the TPCI octet without the APCI bits (0 for
// connectionless communication).
func SyncRequest(key Key, code cemi.MessageCode, src, dst knx.IndividualAddress, tpci byte, seq uint64, serial, challenge [6]byte) (*cemi.LData, error) {
	if seq > MaxSequence {
		return nil, fmt.Errorf("%w: datasecure: sequence %d exceeds 48 bits", knx.ErrInvalidValue, seq)
	}
	scf := SyncRequestSCF.Byte()
	tpdu := []byte{tpci&0xFC | byte(apdu.SecureService>>8), byte(apdu.SecureService & 0xFF), scf}
	f := syncFrame(code, src, dst, make([]byte, syncLen))
	nonce := put48(seq)
	cipher, mac := sealCCM(key, f, tpdu[0], nonce, append([]byte{scf}, serial[:]...), challenge[:])
	tpdu = append(append(append(append(tpdu, nonce[:]...), serial[:]...), cipher...), mac...)
	f.TPDU = tpdu
	return f, nil
}

// SyncReq is a verified S-A_Sync_Req.
type SyncReq struct {
	Sequence  uint64 // the requester's sequence number
	Serial    [6]byte
	Challenge [6]byte
}

// OpenSyncRequest verifies an S-A_Sync_Req with the tool key of its
// destination.
func OpenSyncRequest(key Key, f *cemi.LData) (SyncReq, error) {
	var r SyncReq
	if !IsSecure(f) || len(f.TPDU) != syncLen || ParseSCF(f.TPDU[2]).Service != SSyncReq {
		return r, fmt.Errorf("%w: datasecure: not an S-A_Sync_Req", knx.ErrMalformed)
	}
	var nonce [6]byte
	copy(nonce[:], f.TPDU[3:9])
	copy(r.Serial[:], f.TPDU[9:15])
	plain, err := openCCM(key, f, f.TPDU[0], nonce, append([]byte{f.TPDU[2]}, r.Serial[:]...), f.TPDU[15:21], f.TPDU[21:])
	if err != nil {
		return r, err
	}
	r.Sequence = uint48(nonce)
	copy(r.Challenge[:], plain)
	return r, nil
}

// SyncResponse returns the S-A_Sync_Res from src to dst for a request's
// challenge: remote is src's next sending sequence number, local the next
// sequence number src accepts from dst; random is the nonce; tpci as for
// SyncRequest.
func SyncResponse(key Key, code cemi.MessageCode, src, dst knx.IndividualAddress, tpci byte, challenge, random [6]byte, remote, local uint64) (*cemi.LData, error) {
	if remote > MaxSequence || local > MaxSequence {
		return nil, fmt.Errorf("%w: datasecure: sequence exceeds 48 bits", knx.ErrInvalidValue)
	}
	scf := SyncResponseSCF.Byte()
	tpdu := []byte{tpci&0xFC | byte(apdu.SecureService>>8), byte(apdu.SecureService & 0xFF), scf}
	f := syncFrame(code, src, dst, make([]byte, syncLen))
	r, l := put48(remote), put48(local)
	cipher, mac := sealCCM(key, f, tpdu[0], random, []byte{scf}, append(r[:], l[:]...))
	var x [6]byte
	for i := range x {
		x[i] = challenge[i] ^ random[i]
	}
	f.TPDU = append(append(append(tpdu, x[:]...), cipher...), mac...)
	return f, nil
}

// OpenSyncResponse verifies an S-A_Sync_Res to the request with
// challenge and returns its sequence numbers.
func OpenSyncResponse(key Key, f *cemi.LData, challenge [6]byte) (remote, local uint64, err error) {
	if !IsSecure(f) || len(f.TPDU) != syncLen || ParseSCF(f.TPDU[2]).Service != SSyncRes {
		return 0, 0, fmt.Errorf("%w: datasecure: not an S-A_Sync_Res", knx.ErrMalformed)
	}
	var random [6]byte
	for i := range random {
		random[i] = f.TPDU[3+i] ^ challenge[i]
	}
	plain, err := openCCM(key, f, f.TPDU[0], random, []byte{f.TPDU[2]}, f.TPDU[9:21], f.TPDU[21:])
	if err != nil {
		return 0, 0, err
	}
	var r, l [6]byte
	copy(r[:], plain[:6])
	copy(l[:], plain[6:])
	return uint48(r), uint48(l), nil
}
