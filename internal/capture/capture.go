// SPDX-License-Identifier: MIT

// Package capture reads recorded KNX traffic for tests: classic pcap and
// pcapng files, gzip-compressed or not, and the K12 text files of
// Tektronix/Wireshark. It keeps the two transports apart:
//
//   - KNX TP1 frames as received on the twisted pair (control field to
//     check octet), from a capture whose interface declares link type 0
//     (DLT_NULL) although every packet is a whole TP1 frame: the files of
//     the knx-datasets bundle were written that way by gopacket (see
//     testdata/captures/README.md). [TPLinkType] names that link type; no
//     other link type is read as TP1.
//   - KNXnet/IP frames carried in IPv4 UDP datagrams and TCP streams over
//     Ethernet. A datagram is returned whole (it may hold more than one
//     frame); a TCP stream is reassembled per direction by sequence
//     number and cut into frames by their total length.
//
// It is test infrastructure for testdata/captures and is not part of the
// public API. It reads files from this repository or its capture cache,
// not untrusted input, but it still checks every length it reads.
package capture

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TPFrame is one KNX TP1 frame as recorded on the bus.
type TPFrame struct {
	Frame int       // 1-based frame number in the file
	Time  time.Time // capture time stamp (UTC)
	Data  []byte    // control field .. check octet
}

// Transport names how a KNXnet/IP frame was carried.
type Transport string

// Transports.
const (
	UDP Transport = "udp"
	TCP Transport = "tcp"
)

// Datagram is the KNXnet/IP payload of one UDP datagram, or one frame cut
// from a TCP stream.
type Datagram struct {
	Frame     int // the frame that carried it (TCP: that completed it)
	Time      time.Time
	Transport Transport
	Src, Dst  netip.AddrPort
	Data      []byte
}

// File is the KNX content of one capture file.
type File struct {
	Frames int        // frames in the file
	TP     []TPFrame  // TP1 frames in frame order
	IP     []Datagram // KNXnet/IP datagrams and TCP frames in order
	// TCPRest counts stream octets after the last whole KNXnet/IP frame of
	// a TCP direction on the KNXnet/IP port (a frame with a wrong header,
	// or cut off by the end of the capture: IP holds them as one more
	// datagram), and TCPGaps the directions with missing segments;
	// nothing after a gap is read.
	TCPRest, TCPGaps int
	Other            map[string]int // frames of no interest, by kind
}

// ErrFormat reports a file that is not a capture this package reads, or
// is cut short.
var ErrFormat = errors.New("capture: unsupported or malformed capture file")

// Link-layer header types (tcpdump.org/linktypes.html).
const (
	// TPLinkType is the link type the knx-datasets captures declare for
	// their TP1 frames: 0, DLT_NULL. The packets carry no loopback header.
	TPLinkType = 0
	linkEther  = 1
)

const (
	etherIPv4 = 0x0800
	etherVLAN = 0x8100
	protoTCP  = 6
	protoUDP  = 17
)

// ReadFile reads a capture file.
func ReadFile(path string) (*File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	return Read(b)
}

// maxGunzip bounds a decompressed capture.
const maxGunzip = 64 << 20

// Read parses a capture held in memory.
func Read(b []byte) (*File, error) {
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		z, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFormat, err)
		}
		u, err := io.ReadAll(io.LimitReader(z, maxGunzip+1))
		if err != nil || len(u) > maxGunzip {
			return nil, fmt.Errorf("%w: gzip: %v", ErrFormat, err)
		}
		b = u
	}
	frames, err := packets(b)
	if err != nil {
		return nil, err
	}
	r := &reader{f: &File{Frames: len(frames), Other: map[string]int{}}, streams: map[flow]*stream{}}
	for i, p := range frames {
		r.frame(i+1, p)
	}
	r.flush()
	return r.f, nil
}

// packet is one link-layer frame.
type packet struct {
	link uint32
	ts   time.Time
	data []byte
}

func packets(b []byte) ([]packet, error) {
	if len(b) < 4 {
		return nil, ErrFormat
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		return pcapPackets(b, binary.LittleEndian, false)
	case 0xa1b23c4d:
		return pcapPackets(b, binary.LittleEndian, true)
	case 0xd4c3b2a1:
		return pcapPackets(b, binary.BigEndian, false)
	case 0x4d3cb2a1:
		return pcapPackets(b, binary.BigEndian, true)
	case 0x0a0d0d0a:
		return pcapngPackets(b)
	}
	if bytes.HasPrefix(b, []byte("+---------+")) {
		return k12Packets(b)
	}
	return nil, ErrFormat
}

func pcapPackets(b []byte, bo binary.ByteOrder, nano bool) ([]packet, error) {
	if len(b) < 24 {
		return nil, ErrFormat
	}
	link := bo.Uint32(b[20:24]) & 0x0fffffff
	var out []packet
	for off := 24; off < len(b); {
		if len(b)-off < 16 {
			return nil, ErrFormat
		}
		sec, frac := int64(bo.Uint32(b[off:])), int64(bo.Uint32(b[off+4:]))
		n := int(bo.Uint32(b[off+8 : off+12]))
		off += 16
		if n > len(b)-off {
			return nil, ErrFormat
		}
		if !nano {
			frac *= 1000
		}
		out = append(out, packet{link: link, ts: time.Unix(sec, frac).UTC(), data: b[off : off+n]})
		off += n
	}
	return out, nil
}

type ngInterface struct {
	link uint32
	unit int64 // time stamp units per second
}

func pcapngPackets(b []byte) ([]packet, error) {
	var (
		bo  binary.ByteOrder = binary.LittleEndian
		ifs []ngInterface
		out []packet
	)
	for off := 0; off < len(b); {
		if len(b)-off < 12 {
			return nil, ErrFormat
		}
		typ := bo.Uint32(b[off:])
		if typ == 0x0a0d0d0a { // section header: byte order from its magic
			switch binary.LittleEndian.Uint32(b[off+8:]) {
			case 0x1a2b3c4d:
				bo = binary.LittleEndian
			case 0x4d3c2b1a:
				bo = binary.BigEndian
			default:
				return nil, ErrFormat
			}
			ifs = ifs[:0]
		}
		n := int(bo.Uint32(b[off+4:]))
		if n < 12 || n%4 != 0 || n > len(b)-off {
			return nil, ErrFormat
		}
		body := b[off+8 : off+n-4]
		switch typ {
		case 1: // interface description
			if len(body) < 8 {
				return nil, ErrFormat
			}
			ifs = append(ifs, ngInterface{link: uint32(bo.Uint16(body)), unit: tsResolution(body[8:], bo)})
		case 6: // enhanced packet
			if len(body) < 20 {
				return nil, ErrFormat
			}
			ifc := int(bo.Uint32(body))
			capLen := int(bo.Uint32(body[12:]))
			if ifc >= len(ifs) || capLen > len(body)-20 {
				return nil, ErrFormat
			}
			ts := int64(bo.Uint32(body[4:]))<<32 | int64(bo.Uint32(body[8:]))
			u := ifs[ifc].unit
			out = append(out, packet{link: ifs[ifc].link, ts: time.Unix(ts/u, (ts%u)*(1e9/u)).UTC(), data: body[20 : 20+capLen]})
		}
		off += n
	}
	return out, nil
}

// tsResolution reads the if_tsresol option of an interface description
// block (default microseconds).
func tsResolution(opts []byte, bo binary.ByteOrder) int64 {
	for len(opts) >= 4 {
		code, n := bo.Uint16(opts), int(bo.Uint16(opts[2:]))
		if code == 0 || 4+n > len(opts) {
			break
		}
		if code == 9 && n >= 1 {
			if v := opts[4]; v&0x80 == 0 && v <= 9 {
				u := int64(1)
				for range v {
					u *= 10
				}
				return u
			}
		}
		opts = opts[4+(n+3)&^3:]
	}
	return 1e6
}

// k12Packets reads a K12 text file: records separated by a "+----" line,
// each a "HH:MM:SS,mmm,uuu   ETHER" line and a "|0   |xx|xx|...|" line of
// octets. The file holds no date; the time stamps are on 1970-01-01.
func k12Packets(b []byte) ([]packet, error) {
	var (
		out []packet
		ts  time.Time
		hdr bool
	)
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		switch {
		case line == "" || strings.HasPrefix(line, "+-"):
		case strings.HasPrefix(line, "|0 "):
			if !hdr {
				return nil, ErrFormat
			}
			fields := strings.Split(strings.Trim(line, "|"), "|")
			data := make([]byte, 0, len(fields))
			for _, h := range fields[1:] {
				v, err := hex.DecodeString(h)
				if err != nil || len(v) != 1 {
					return nil, ErrFormat
				}
				data = append(data, v[0])
			}
			out = append(out, packet{link: linkEther, ts: ts, data: data})
			hdr = false
		default:
			f := strings.Fields(line)
			if len(f) != 2 || f[1] != "ETHER" {
				return nil, ErrFormat
			}
			t, err := k12Time(f[0])
			if err != nil {
				return nil, err
			}
			ts, hdr = t, true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	return out, nil
}

// k12Time parses "HH:MM:SS,mmm,uuu".
func k12Time(s string) (time.Time, error) {
	p := strings.Split(s, ",")
	if len(p) != 3 {
		return time.Time{}, ErrFormat
	}
	c, err := time.Parse("15:04:05", p[0])
	if err != nil {
		return time.Time{}, ErrFormat
	}
	ms, err1 := strconv.Atoi(p[1])
	us, err2 := strconv.Atoi(p[2])
	if err1 != nil || err2 != nil || ms > 999 || us > 999 {
		return time.Time{}, ErrFormat
	}
	return time.Date(1970, 1, 1, c.Hour(), c.Minute(), c.Second(), ms*1e6+us*1e3, time.UTC), nil
}

// flow is one direction of a TCP connection.
type flow struct{ src, dst netip.AddrPort }

// segment is a TCP segment's payload.
type segment struct {
	seq   uint32
	frame int
	ts    time.Time
	data  []byte
}

type stream struct {
	order int // first seen
	segs  []segment
}

type reader struct {
	f       *File
	streams map[flow]*stream
}

func (r *reader) frame(num int, p packet) {
	switch p.link {
	case TPLinkType:
		r.f.TP = append(r.f.TP, TPFrame{Frame: num, Time: p.ts, Data: p.data})
	case linkEther:
		r.ethernet(num, p.ts, p.data)
	default:
		r.f.Other[fmt.Sprintf("link %d", p.link)]++
	}
}

func (r *reader) ethernet(num int, ts time.Time, d []byte) {
	if len(d) < 14 {
		r.f.Other["short ethernet"]++
		return
	}
	typ := binary.BigEndian.Uint16(d[12:14])
	if typ == etherVLAN && len(d) >= 18 {
		typ = binary.BigEndian.Uint16(d[16:18])
		d = d[4:]
	}
	if typ != etherIPv4 {
		r.f.Other[fmt.Sprintf("ethertype 0x%04x", typ)]++
		return
	}
	r.ipv4(num, ts, d[14:])
}

func (r *reader) ipv4(num int, ts time.Time, d []byte) {
	if len(d) < 20 || d[0]>>4 != 4 {
		r.f.Other["bad ipv4"]++
		return
	}
	ihl := int(d[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(d[2:4]))
	if ihl < 20 || total < ihl || total > len(d) {
		r.f.Other["bad ipv4"]++
		return
	}
	if binary.BigEndian.Uint16(d[6:8])&0x3fff != 0 {
		r.f.Other["ipv4 fragment"]++
		return
	}
	src, dst := netip.AddrFrom4([4]byte(d[12:16])), netip.AddrFrom4([4]byte(d[16:20]))
	p := d[ihl:total]
	switch d[9] {
	case protoUDP:
		if len(p) < 8 {
			r.f.Other["bad udp"]++
			return
		}
		n := int(binary.BigEndian.Uint16(p[4:6]))
		if n < 8 || n > len(p) {
			r.f.Other["bad udp"]++
			return
		}
		data := p[8:n]
		sport, dport := binary.BigEndian.Uint16(p[0:2]), binary.BigEndian.Uint16(p[2:4])
		if !isKNXnetIP(data) && (sport != Port || len(data) == 0) && (dport != Port || len(data) == 0) {
			r.f.Other["udp other"]++
			return
		}
		r.f.IP = append(r.f.IP, Datagram{Frame: num, Time: ts, Transport: UDP,
			Src: netip.AddrPortFrom(src, sport), Dst: netip.AddrPortFrom(dst, dport), Data: data})
	case protoTCP:
		if len(p) < 20 || int(p[12]>>4)*4 < 20 || int(p[12]>>4)*4 > len(p) {
			r.f.Other["bad tcp"]++
			return
		}
		data := p[int(p[12]>>4)*4:]
		seq := binary.BigEndian.Uint32(p[4:8])
		k := flow{netip.AddrPortFrom(src, binary.BigEndian.Uint16(p[0:2])), netip.AddrPortFrom(dst, binary.BigEndian.Uint16(p[2:4]))}
		s := r.streams[k]
		if s == nil {
			s = &stream{order: len(r.streams)}
			r.streams[k] = s
		}
		if p[13]&0x02 != 0 { // SYN: the data starts at seq+1
			seq++
		}
		if len(data) > 0 || p[13]&0x02 != 0 {
			s.segs = append(s.segs, segment{seq: seq, frame: num, ts: ts, data: data})
		}
	default:
		r.f.Other[fmt.Sprintf("ip proto %d", d[9])]++
	}
}

// Port is the KNXnet/IP port. A UDP datagram to or from it is returned
// whatever it holds (the recordings hold frames with a wrong header
// length or version, sent on purpose); on another port only a payload
// that starts like a KNXnet/IP header is.
const Port = 3671

// isKNXnetIP reports a payload that starts with a KNXnet/IP header
// (header length 6, protocol version 1.0).
func isKNXnetIP(b []byte) bool { return len(b) >= 6 && b[0] == 0x06 && b[1] == 0x10 }

// flush reassembles every TCP direction and cuts it into KNXnet/IP frames,
// then puts all datagrams in frame order (stable: TCP frames completed by
// the same segment keep their stream order).
func (r *reader) flush() {
	flows := make([]flow, 0, len(r.streams))
	for k := range r.streams {
		flows = append(flows, k)
	}
	sort.Slice(flows, func(i, j int) bool { return r.streams[flows[i]].order < r.streams[flows[j]].order })
	for _, k := range flows {
		r.reassemble(k, r.streams[k])
	}
	sort.SliceStable(r.f.IP, func(i, j int) bool { return r.f.IP[i].Frame < r.f.IP[j].Frame })
}

// reassemble orders a direction's segments by sequence number (relative
// to the first), drops retransmitted octets and cuts frames. A frame is
// stamped with the segment that completed it.
func (r *reader) reassemble(k flow, s *stream) {
	if len(s.segs) == 0 {
		return
	}
	base := s.segs[0].seq
	sort.SliceStable(s.segs, func(i, j int) bool { return s.segs[i].seq-base < s.segs[j].seq-base })
	var (
		buf   []byte
		ends  []segment // the segment that ends at each octet boundary
		next  = uint32(0)
		start = 0
	)
	for _, g := range s.segs {
		off := g.seq - base
		if off > next {
			r.f.TCPGaps++
			break
		}
		if skip := next - off; int(skip) < len(g.data) {
			buf = append(buf, g.data[skip:]...)
			next = off + uint32(len(g.data))
			// The octets up to next are complete once the latest of their
			// segments has arrived.
			e := segment{seq: next, frame: g.frame, ts: g.ts}
			if n := len(ends); n > 0 && ends[n-1].frame > e.frame {
				e.frame, e.ts = ends[n-1].frame, ends[n-1].ts
			}
			ends = append(ends, e)
		}
	}
	for len(buf)-start >= 6 && isKNXnetIP(buf[start:]) {
		n := int(binary.BigEndian.Uint16(buf[start+4:]))
		if n < 6 || len(buf)-start < n {
			break
		}
		end := uint32(start + n)
		i := sort.Search(len(ends), func(i int) bool { return ends[i].seq >= end })
		g := ends[i]
		r.f.IP = append(r.f.IP, Datagram{Frame: g.frame, Time: g.ts, Transport: TCP, Src: k.src, Dst: k.dst, Data: buf[start : start+n]})
		start += n
	}
	if start < len(buf) && (k.src.Port() == Port || k.dst.Port() == Port) {
		// What follows the last whole frame (a frame with a wrong header
		// or cut off by the end of the capture) is returned as one
		// datagram, for the decoder to refuse.
		g := ends[len(ends)-1]
		r.f.IP = append(r.f.IP, Datagram{Frame: g.frame, Time: g.ts, Transport: TCP, Src: k.src, Dst: k.dst, Data: buf[start:]})
		r.f.TCPRest += len(buf) - start
	}
}
