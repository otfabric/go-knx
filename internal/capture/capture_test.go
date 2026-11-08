// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"testing"
)

// pcapFile builds a classic pcap of link type link with the packets.
func pcapFile(bo binary.AppendByteOrder, link uint32, pkts ...[]byte) []byte {
	b := bo.AppendUint32(nil, 0xa1b2c3d4)
	b = bo.AppendUint16(b, 2)
	b = bo.AppendUint16(b, 4)
	b = append(b, make([]byte, 8)...)
	b = bo.AppendUint32(b, 65535)
	b = bo.AppendUint32(b, link)
	for i, p := range pkts {
		b = bo.AppendUint32(b, uint32(1000+i))
		b = bo.AppendUint32(b, 0)
		b = bo.AppendUint32(b, uint32(len(p)))
		b = bo.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return b
}

// udpFrame is an Ethernet/IPv4/UDP frame.
func udpFrame(sport, dport uint16, payload []byte) []byte {
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, protoUDP, 0, 0, 192, 168, 0, 1, 192, 168, 0, 2}
	binary.BigEndian.PutUint16(ip[2:], uint16(20+8+len(payload)))
	udp := binary.BigEndian.AppendUint16(nil, sport)
	udp = binary.BigEndian.AppendUint16(udp, dport)
	udp = binary.BigEndian.AppendUint16(udp, uint16(8+len(payload)))
	udp = append(udp, 0, 0)
	eth := append(make([]byte, 12), 0x08, 0x00)
	return append(append(append(eth, ip...), udp...), payload...)
}

// tcpFrame is an Ethernet/IPv4/TCP segment.
func tcpFrame(sport, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, protoTCP, 0, 0, 192, 168, 0, 1, 192, 168, 0, 2}
	binary.BigEndian.PutUint16(ip[2:], uint16(20+20+len(payload)))
	tcp := binary.BigEndian.AppendUint16(nil, sport)
	tcp = binary.BigEndian.AppendUint16(tcp, dport)
	tcp = binary.BigEndian.AppendUint32(tcp, seq)
	tcp = append(tcp, 0, 0, 0, 0, 0x50, flags, 0, 0, 0, 0, 0, 0)
	eth := append(make([]byte, 12), 0x08, 0x00)
	return append(append(append(eth, ip...), tcp...), payload...)
}

var search = []byte{0x06, 0x10, 0x02, 0x01, 0x00, 0x0e, 0x08, 0x01, 192, 168, 0, 1, 0x0e, 0x57}

func TestReadPcapUDPAndTCP(t *testing.T) {
	frames := [][]byte{
		udpFrame(3671, 3671, append(append([]byte{}, search...), search...)), // two frames in one datagram
		udpFrame(1234, 3671, []byte{0x05, 0x10}),                             // the KNXnet/IP port: kept
		udpFrame(1234, 5000, []byte{0x05, 0x10}),                             // another port: not KNXnet/IP
		tcpFrame(5000, 3671, 99, 0x02, nil),                                  // SYN
		tcpFrame(5000, 3671, 100+6, 0x18, search[6:]),                        // out of order
		tcpFrame(5000, 3671, 100, 0x18, search[:6]),
		tcpFrame(5000, 3671, 100, 0x18, search[:6]),                  // retransmission
		tcpFrame(5000, 3671, 100+14, 0x18, []byte{0x06, 0x10, 0x02}), // cut off
	}
	for _, bo := range []binary.AppendByteOrder{binary.LittleEndian, binary.BigEndian} {
		f, err := Read(pcapFile(bo, linkEther, frames...))
		if err != nil {
			t.Fatal(err)
		}
		if f.Frames != len(frames) || len(f.IP) != 4 || f.Other["udp other"] != 1 || f.TCPRest != 3 {
			t.Fatalf("%+v", f)
		}
		fr, rest := Frames(f.IP[0].Data)
		if len(fr) != 2 || len(rest) != 0 {
			t.Fatalf("frames %d rest %d", len(fr), len(rest))
		}
		if f.IP[2].Transport != TCP || !bytes.Equal(f.IP[2].Data, search) || f.IP[2].Frame != 6 {
			t.Fatalf("TCP frame %+v", f.IP[2])
		}
		if !bytes.Equal(f.IP[3].Data, []byte{0x06, 0x10, 0x02}) {
			t.Fatalf("TCP rest %+v", f.IP[3])
		}
	}
}

func TestReadTPAndGzip(t *testing.T) {
	tp := []byte{0xBC, 0x11, 0xDC, 0x0D, 0x70, 0xD1, 0x00, 0x80, 0xA2}
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	_, _ = w.Write(pcapFile(binary.LittleEndian, TPLinkType, tp, tp))
	_ = w.Close()
	f, err := Read(z.Bytes())
	if err != nil || len(f.TP) != 2 || !bytes.Equal(f.TP[1].Data, tp) || f.TP[1].Frame != 2 {
		t.Fatalf("%+v %v", f, err)
	}
	st := Analyze(f)
	if st.TP.Decoded != 2 || st.TP.Reencoded != 2 || st.TP.TPDU.Services["A_GroupValue_Write"] != 2 {
		t.Fatalf("%+v", st.TP)
	}
	if f, err := Read(pcapFile(binary.LittleEndian, 147, tp)); err != nil || f.Other["link 147"] != 1 {
		t.Fatalf("%+v %v", f, err)
	}
}

func TestReadK12(t *testing.T) {
	frame := udpFrame(3671, 3671, search)
	var b bytes.Buffer
	b.WriteString("+---------+---------------+----------+\r\n06:42:02,070,831   ETHER\r\n|0   ")
	for _, c := range frame {
		b.WriteString("|")
		b.WriteString(string("0123456789abcdef"[c>>4]) + string("0123456789abcdef"[c&15]))
	}
	b.WriteString("|\r\n\r\n")
	f, err := Read(b.Bytes())
	if err != nil || len(f.IP) != 1 || !bytes.Equal(f.IP[0].Data, search) {
		t.Fatalf("%+v %v", f, err)
	}
	if got := f.IP[0].Time; got.Hour() != 6 || got.Nanosecond() != 70831000 {
		t.Fatalf("time %v", got)
	}
}

func TestReadMalformed(t *testing.T) {
	good := pcapFile(binary.LittleEndian, linkEther, udpFrame(3671, 3671, search))
	for name, b := range map[string][]byte{
		"empty":         nil,
		"unknown":       []byte("not a capture"),
		"short header":  good[:20],
		"cut packet":    good[:len(good)-3],
		"bad gzip":      {0x1f, 0x8b, 0x00},
		"k12 data line": []byte("+---------+\n|0   |00|\n"),
		"k12 hex":       []byte("+---------+\n00:00:00,000,000   ETHER\n|0   |zz|\n"),
		"k12 time":      []byte("+---------+\n00:00:00   ETHER\n"),
		"pcapng short":  {0x0a, 0x0d, 0x0d, 0x0a, 12, 0, 0, 0},
	} {
		if _, err := Read(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCSVHelpers(t *testing.T) {
	if CSVService("A_GroupValue_Write_PDU") != "A_GroupValue_Write" || CSVService("T_ACK-PDU") != "T_ACK" {
		t.Fatal("CSVService")
	}
	if v, err := CSVValue("0X0108"); err != nil || !bytes.Equal(v, []byte{1, 8}) {
		t.Fatalf("% X %v", v, err)
	}
	row := "Pkt; TimeStamp; a; b; c; MessageSize; MessageChecksum; SA_text; SA_int; DA_text; DA_int; KNX_Info; i; c; KNX_Value; Msg\n" +
		"1; t; 0; 0; 0; 9; 0XA2; 1.1.220; 0X11DC; 1/5/112; 0XD70; A_GroupValue_Write_PDU; 0X80; 0X80; 0X00; 0XBC11DC0D70D10080A2\n"
	var got []CSVRow
	if err := ReadCSV(bytes.NewReader([]byte(row)), func(r CSVRow) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Checksum != 0xA2 || got[0].Dest != "1/5/112" || len(got[0].Msg) != 9 {
		t.Fatalf("%+v", got)
	}
	if err := ReadCSV(bytes.NewReader([]byte("h\n1; 2\n")), func(CSVRow) error { return nil }); err == nil {
		t.Fatal("short row accepted")
	}
}
