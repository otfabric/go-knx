// SPDX-License-Identifier: MIT

package capture

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// CSVRow is one packet of a knx-datasets CSV export: the dataset
// authors' own decode of the capture, an oracle independent of go-knx.
type CSVRow struct {
	Pkt      int
	Checksum byte   // MessageChecksum
	Source   string // SA_text, "1.1.220"
	Dest     string // DA_text, "1/5/112" or "1.1.142"
	Info     string // KNX_Info, "A_GroupValue_Write_PDU", "T_ACK-PDU"
	Value    string // KNX_Value as written, "0X00"
	Msg      []byte // the whole TP1 frame
}

// ReadCSV reads a knx-datasets hexadecimal CSV export ("; "-separated,
// a header line, numbers as 0X..).
func ReadCSV(r io.Reader, each func(CSVRow) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		if line == 1 {
			continue
		}
		f := strings.Split(sc.Text(), "; ")
		if len(f) < 16 {
			return fmt.Errorf("csv line %d: %d fields", line, len(f))
		}
		var row CSVRow
		if _, err := fmt.Sscan(f[0], &row.Pkt); err != nil {
			return fmt.Errorf("csv line %d: %w", line, err)
		}
		ck, err := hexField(f[6])
		if err != nil || len(ck) != 1 {
			return fmt.Errorf("csv line %d: checksum %q", line, f[6])
		}
		row.Checksum = ck[0]
		row.Source, row.Dest, row.Info, row.Value = f[7], f[9], f[11], f[14]
		if row.Msg, err = hexField(f[15]); err != nil {
			return fmt.Errorf("csv line %d: message %q", line, f[15])
		}
		if err := each(row); err != nil {
			return err
		}
	}
	return sc.Err()
}

// hexField decodes "0XA2" (an odd digit count gets a leading zero).
func hexField(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0X"), "0x")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

// CSVService maps a KNX_Info name of the CSV to go-knx's service name
// (ServiceName): "A_GroupValue_Write_PDU" is "A_GroupValue_Write",
// "T_ACK-PDU" is "T_ACK".
func CSVService(info string) string {
	return strings.TrimSuffix(strings.TrimSuffix(info, "_PDU"), "-PDU")
}

// CSVValue decodes KNX_Value: the 6-bit value or the data octets as the
// CSV writes them ("0X0" for zero, "0X0018F5"). It returns the value
// with leading zero octets removed, for comparison.
func CSVValue(s string) ([]byte, error) {
	b, err := hexField(s)
	if err != nil {
		return nil, err
	}
	return bytes.TrimLeft(b, "\x00"), nil
}
