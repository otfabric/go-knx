// SPDX-License-Identifier: MIT

package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
)

// oracleDiffs are the classified differences between go-knx's service
// type and cEMI message code counts and Wireshark's, per capture:
// {go-knx, Wireshark}. Every other count must be equal.
//
//   - TCP port 2152 is GTP's: Wireshark dissects the KNXnet/IP Secure
//     session the client opened from that port as GTP (0x0950-0x0952).
//   - Wireshark's TCP analysis shows some streams whose first segment
//     it did not see as "Continuation Data" (0x0203, 0x020B, 0x020C).
//   - Frame 7 of 02-devicemanagement goes to UDP port 3672; Wireshark
//     dissects KNXnet/IP on 3671 only (0x0310, cEMI 0xFC).
var oracleDiffs = map[string]map[string][2]int{
	"wireshark-14825/test-tool_abb-ipr-s_01-core.txt": {
		"0x0203": {145, 142}, "0x020B": {113, 110}, "0x0201": {13, 12}, "0x020C": {88, 85},
		"0x0950": {108, 92}, "0x0951": {9, 8}, "0x0952": {9, 8},
	},
	"wireshark-14825/test-tool_abb-ipr-s_02-devicemanagement.txt": {"0x0310": {164, 163}, "cemi 0xFC": {67, 66}},
	"wireshark-14825/test-tool_abb-ipr-s_03-tunneling.txt":        {"0x0950": {170, 168}, "0x0951": {29, 28}, "0x0952": {29, 28}},
}

// TestCorpus re-derives every manifest entry from its committed capture:
// the SHA256, and go-knx's decode and re-encode counts must equal the
// manifest, and the counts must agree with the independent decoder's
// (Wireshark, or the dataset authors' CSV export) except for the
// classified differences.
func TestCorpus(t *testing.T) {
	man, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	var tp, ip, files int
	for _, e := range man.Files {
		t.Run(e.File, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(Dir(), filepath.FromSlash(e.File)))
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != e.SHA256 || int64(len(raw)) != e.Size {
				t.Fatalf("SHA256 %x size %d, manifest %s %d", sum, len(raw), e.SHA256, e.Size)
			}
			f, err := Read(raw)
			if err != nil {
				t.Fatal(err)
			}
			st := Analyze(f)
			if !reflect.DeepEqual(st, e.Stats) {
				t.Errorf("stats differ from the manifest (make captures-generate after a deliberate change)\n got %+v\nwant %+v", st, e.Stats)
			}
			files++
			if e.Oracle == nil {
				t.Fatal("no oracle counts")
			}
			switch e.Transport {
			case "tp1":
				checkTP(t, st.TP, e.Oracle)
				tp += st.TP.Frames
			case "knxnetip":
				checkIP(t, e.File, st.IP, e.Oracle)
				ip += st.IP.Frames
			default:
				t.Fatalf("transport %q", e.Transport)
			}
		})
	}
	t.Logf("%d captures: %d TP1 frames, %d KNXnet/IP frames", files, tp, ip)
	if files != 18 {
		t.Fatalf("%d captures, want 18", files)
	}
}

// checkTP: every recorded TP1 frame decodes, check octet included, and
// encodes again to its octets; its TPDU decodes and encodes again; the
// services equal the dataset authors' decode.
func checkTP(t *testing.T, st *TPStats, o *Counts) {
	t.Helper()
	if st == nil || st.Frames == 0 {
		t.Fatal("no TP1 frames")
	}
	if st.Decoded != st.Frames || st.Reencoded != st.Frames || st.CEMI != st.Frames {
		t.Errorf("%d frames: %d decoded, %d re-encoded, %d cEMI round trips", st.Frames, st.Decoded, st.Reencoded, st.CEMI)
	}
	if st.TPDU.Decoded != st.Frames || st.TPDU.Reencoded != st.Frames {
		t.Errorf("%d frames: %d TPDUs decoded, %d re-encoded", st.Frames, st.TPDU.Decoded, st.TPDU.Reencoded)
	}
	if !maps.Equal(st.TPDU.Services, o.Services) {
		t.Errorf("services\n go-knx %v\n %s %v", st.TPDU.Services, o.Tool, o.Services)
	}
}

// checkIP: every KNXnet/IP frame and cEMI frame go-knx decodes encodes
// again to the recorded octets; service and message code counts agree
// with Wireshark's but for the classified differences.
func checkIP(t *testing.T, file string, st *IPStats, o *Counts) {
	t.Helper()
	if st == nil || st.Frames == 0 {
		t.Fatal("no KNXnet/IP frames")
	}
	if st.Reencoded != st.Decoded || st.CEMIReencoded != st.CEMIDecoded || st.TPDU.Reencoded != st.TPDU.Decoded {
		t.Errorf("re-encoded: %d of %d frames, %d of %d cEMI frames, %d of %d TPDUs",
			st.Reencoded, st.Decoded, st.CEMIReencoded, st.CEMIDecoded, st.TPDU.Reencoded, st.TPDU.Decoded)
	}
	want := oracleDiffs[file]
	seen := 0
	compare := func(prefix string, a, b map[string]int) {
		for k := range joinKeys(a, b) {
			if a[k] == b[k] {
				continue
			}
			d, ok := want[prefix+k]
			if !ok || d != [2]int{a[k], b[k]} {
				t.Errorf("%s%s: go-knx %d, Wireshark %d (classified: %v)", prefix, k, a[k], b[k], d)
			}
			seen++
		}
	}
	compare("", st.ServiceCodes, o.Services)
	compare("cemi ", st.CEMICodeOctets, o.CEMICodes)
	if seen != len(want) {
		t.Errorf("%d classified differences seen, %d listed", seen, len(want))
	}
}

func joinKeys(a, b map[string]int) map[string]bool {
	k := map[string]bool{}
	for x := range a {
		k[x] = true
	}
	for x := range b {
		k[x] = true
	}
	return k
}

// TestCorpusCSV compares every TP1 frame with the dataset authors' CSV
// export, row by row: the octets, the check octet, the addresses, the
// service and the value. The CSV files are over 50 MB and not committed:
// KNX_CAPTURE_EXTENDED=1 (make captures-extended) runs it from the cache.
func TestCorpusCSV(t *testing.T) {
	if os.Getenv("KNX_CAPTURE_EXTENDED") != "1" {
		t.Skip("KNX_CAPTURE_EXTENDED=1 compares with the CSV exports (make captures-extended)")
	}
	man, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range man.Oracles {
		t.Run(o.For, func(t *testing.T) {
			f, err := Load(o.For)
			if err != nil {
				t.Fatal(err)
			}
			r, err := os.Open(filepath.Join(CacheDir(), filepath.FromSlash(o.File)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			h := sha256.New()
			i := 0
			err = ReadCSV(io.TeeReader(r, h), func(row CSVRow) error {
				if i >= len(f.TP) {
					t.Fatalf("CSV row %d beyond the %d frames", row.Pkt, len(f.TP))
				}
				compareRow(t, f.TP[i], row)
				i++
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
				t.Fatalf("%s: SHA256 %x, manifest %s", o.File, h.Sum(nil), o.SHA256)
			}
			if i != len(f.TP) {
				t.Fatalf("%d CSV rows, %d frames", i, len(f.TP))
			}
			t.Logf("%d frames agree with %s", i, o.Name)
		})
	}
}

func compareRow(t *testing.T, fr TPFrame, row CSVRow) {
	t.Helper()
	if row.Pkt != fr.Frame || !bytes.Equal(row.Msg, fr.Data) {
		t.Fatalf("row %d: % X, frame %d % X", row.Pkt, row.Msg, fr.Frame, fr.Data)
	}
	ld, err := cemi.ParseTP1(fr.Data)
	if err != nil {
		t.Fatalf("frame %d: %v", fr.Frame, err)
	}
	if row.Checksum != fr.Data[len(fr.Data)-1] {
		t.Errorf("frame %d: CSV check octet %02X", fr.Frame, row.Checksum)
	}
	if ld.Source.String() != row.Source || ld.DestinationString() != row.Dest {
		t.Errorf("frame %d: %s -> %s, CSV %s -> %s", fr.Frame, ld.Source, ld.DestinationString(), row.Source, row.Dest)
	}
	p, err := apdu.Parse(ld.TPDU)
	if err != nil {
		t.Fatalf("frame %d: %v", fr.Frame, err)
	}
	if ServiceName(p) != CSVService(row.Info) {
		t.Errorf("frame %d: %s, CSV %s", fr.Frame, ServiceName(p), row.Info)
	}
	// The CSV value is the 6-bit parameter and the data octets as one
	// number: compare without leading zero octets.
	var v []byte
	if !p.TPCI.IsControl() {
		v = bytes.TrimLeft(append([]byte{ld.TPDU[1] & 0x3F}, ld.TPDU[2:]...), "\x00")
	}
	if cv, err := CSVValue(row.Value); err != nil || !bytes.Equal(cv, v) {
		t.Errorf("frame %d: value % X, CSV %s (%v)", fr.Frame, v, row.Value, err)
	}
}
