// SPDX-License-Identifier: MIT

package secure

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/ccm"
	"github.com/otfabric/go-knx/knxnetip"
)

// MaxSequence is the largest 48-bit sequence number or timer value.
const MaxSequence = 1<<48 - 1

// wrapperOverhead is the length of a SECURE_WRAPPER around a frame: the
// header, session identifier, sequence, serial number, message tag and
// MAC.
const wrapperOverhead = knxnetip.HeaderLen + 2 + 6 + 6 + 2 + knxnetip.MACLen

// put48 returns v as 6 octets, big endian.
func put48(v uint64) (b [6]byte) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	copy(b[:], x[2:])
	return b
}

// Uint48 returns the value of a 48-bit sequence or timer field.
func Uint48(b [6]byte) uint64 {
	var x [8]byte
	copy(x[2:], b[:])
	return binary.BigEndian.Uint64(x[:])
}

// Seal encrypts and authenticates a KNXnet/IP frame (header included)
// into a SECURE_WRAPPER: session 0 is secure routing, where seq is the
// timer value.
func Seal(key Key, session uint16, seq uint64, serial [6]byte, tag uint16, frame []byte) (*knxnetip.SecureWrapper, error) {
	if seq > MaxSequence {
		return nil, fmt.Errorf("%w: secure: sequence %d exceeds 48 bits", knx.ErrInvalidValue, seq)
	}
	if len(frame)+wrapperOverhead > knxnetip.MaxFrameLen {
		return nil, fmt.Errorf("%w: secure: frame of %d octets is too long to wrap", knx.ErrInvalidValue, len(frame))
	}
	w := &knxnetip.SecureWrapper{SessionID: session, Sequence: put48(seq), Serial: serial, MessageTag: tag}
	mac := ccm.MAC(key[:], wrapperB0(w, len(frame)), wrapperAD(w, len(frame)), frame)
	w.Encrypted, w.MAC = ccm.CTR(key[:], wrapperCtr0(w), mac, frame)
	return w, nil
}

// Open verifies and decrypts a SECURE_WRAPPER and returns the frame it
// carries. A wrapped SECURE_WRAPPER is refused.
func Open(key Key, w *knxnetip.SecureWrapper) ([]byte, error) {
	frame, mac := ccm.CTR(key[:], wrapperCtr0(w), w.MAC, w.Encrypted)
	want := ccm.MAC(key[:], wrapperB0(w, len(frame)), wrapperAD(w, len(frame)), frame)
	if subtle.ConstantTimeCompare(mac[:], want[:]) != 1 {
		return nil, fmt.Errorf("%w: secure: SECURE_WRAPPER authentication failed", knx.ErrSecurity)
	}
	h, err := knxnetip.ParseHeader(frame)
	if err != nil {
		return nil, err
	}
	if h.Service == knxnetip.SecureWrapperType {
		return nil, fmt.Errorf("%w: secure: nested SECURE_WRAPPER", knx.ErrSecurity)
	}
	return frame, nil
}

func wrapperAD(w *knxnetip.SecureWrapper, n int) []byte {
	b := knxnetip.AppendHeader(make([]byte, 0, 8), knxnetip.SecureWrapperType, wrapperOverhead-knxnetip.HeaderLen+n)
	return binary.BigEndian.AppendUint16(b, w.SessionID)
}

func wrapperB0(w *knxnetip.SecureWrapper, n int) []byte {
	b := make([]byte, 0, 16)
	b = append(b, w.Sequence[:]...)
	b = append(b, w.Serial[:]...)
	b = binary.BigEndian.AppendUint16(b, w.MessageTag)
	return binary.BigEndian.AppendUint16(b, uint16(n))
}

func wrapperCtr0(w *knxnetip.SecureWrapper) []byte {
	b := make([]byte, 0, 16)
	b = append(b, w.Sequence[:]...)
	b = append(b, w.Serial[:]...)
	b = binary.BigEndian.AppendUint16(b, w.MessageTag)
	return append(b, 0xFF, 0x00)
}

// timerNotifyBlocks returns block 0 and counter 0 of a TIMER_NOTIFY.
func timerNotifyBlocks(timer, serial [6]byte, tag uint16) (b0, ctr0 []byte) {
	b0 = make([]byte, 0, 16)
	b0 = append(b0, timer[:]...)
	b0 = append(b0, serial[:]...)
	b0 = binary.BigEndian.AppendUint16(b0, tag)
	ctr0 = append(append([]byte(nil), b0...), 0xFF, 0x00)
	return append(b0, 0, 0), ctr0
}

// NewTimerNotify returns a TIMER_NOTIFY of the timer value, authenticated
// with the backbone key.
func NewTimerNotify(key Key, timer uint64, serial [6]byte, tag uint16) *knxnetip.TimerNotify {
	m := &knxnetip.TimerNotify{Timer: put48(timer & MaxSequence), Serial: serial, MessageTag: tag}
	b0, ctr0 := timerNotifyBlocks(m.Timer, serial, tag)
	mac := ccm.MAC(key[:], b0, timerNotifyHeader(), nil)
	_, m.MAC = ccm.CTR(key[:], ctr0, mac, nil)
	return m
}

// VerifyTimerNotify checks the MAC of a TIMER_NOTIFY.
func VerifyTimerNotify(key Key, m *knxnetip.TimerNotify) error {
	b0, ctr0 := timerNotifyBlocks(m.Timer, m.Serial, m.MessageTag)
	_, mac := ccm.CTR(key[:], ctr0, m.MAC, nil)
	want := ccm.MAC(key[:], b0, timerNotifyHeader(), nil)
	if subtle.ConstantTimeCompare(mac[:], want[:]) != 1 {
		return fmt.Errorf("%w: secure: TIMER_NOTIFY authentication failed", knx.ErrSecurity)
	}
	return nil
}

func timerNotifyHeader() []byte {
	return knxnetip.AppendHeader(nil, knxnetip.TimerNotifyType, 6+6+2+knxnetip.MACLen)
}
