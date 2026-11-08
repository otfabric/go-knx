// SPDX-License-Identifier: MIT

package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerate rewrites the derived fields of manifest.json (SHA256, size,
// go-knx's counts and the oracle counts) from the committed captures,
// tshark and, where cached, the knx-datasets CSV exports. The provenance
// fields are kept as written. Run by make captures-generate.
func TestGenerate(t *testing.T) {
	if os.Getenv("KNX_CAPTURE_GENERATE") != "1" {
		t.Skip("KNX_CAPTURE_GENERATE=1 rewrites manifest.json")
	}
	man, err := LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	v, err := exec.Command("tshark", "--version").Output()
	if err != nil {
		t.Fatalf("tshark: %v", err)
	}
	man.Wireshark = strings.TrimSpace(strings.SplitN(string(v), "\n", 2)[0])
	for i := range man.Files {
		e := &man.Files[i]
		path := filepath.Join(Dir(), filepath.FromSlash(e.File))
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		e.SHA256, e.Size = hex.EncodeToString(sum[:]), int64(len(raw))
		f, err := Read(raw)
		if err != nil {
			t.Fatalf("%s: %v", e.File, err)
		}
		e.Stats = Analyze(f)
		switch e.Transport {
		case "knxnetip":
			e.Oracle = tsharkCounts(t, path)
		case "tp1":
			if c := csvCounts(t, man, e.File); c != nil {
				e.Oracle = c
			}
		}
	}
	b, err := json.MarshalIndent(man, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(), "manifest.json"), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	for _, e := range man.Files {
		fmt.Fprintf(&sums, "%s  %s\n", e.SHA256, e.File)
	}
	if err := os.WriteFile(filepath.Join(Dir(), "SHA256SUMS"), []byte(sums.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// tsharkCounts counts the KNXnet/IP service types and cEMI message codes
// Wireshark decodes, outside ICMP error quotes, and its malformed frames.
func tsharkCounts(t *testing.T, path string) *Counts {
	t.Helper()
	out, err := exec.Command("tshark", "-r", path, "-Y", "kip && !icmp", "-T", "fields", "-E", "separator=;",
		"-e", "knxip.service", "-e", "cemi.mc", "-e", "_ws.malformed").Output()
	if err != nil {
		t.Fatalf("tshark %s: %v", path, err)
	}
	c := &Counts{Tool: "tshark", Services: map[string]int{}, CEMICodes: map[string]int{}}
	for line := range strings.SplitSeq(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ";")
		for _, s := range strings.Split(f[0], ",") {
			if s != "" {
				c.Services[fmt.Sprintf("0x%04X", parseHex(t, s))]++
			}
		}
		for _, s := range strings.Split(f[1], ",") {
			if s != "" {
				c.CEMICodes[fmt.Sprintf("0x%02X", parseHex(t, s))]++
			}
		}
		if f[2] != "" {
			c.Malformed++
		}
	}
	if len(c.CEMICodes) == 0 {
		c.CEMICodes = nil
	}
	return c
}

func parseHex(t *testing.T, s string) uint64 {
	t.Helper()
	var v uint64
	if _, err := fmt.Sscanf(s, "0x%x", &v); err != nil {
		t.Fatalf("tshark value %q: %v", s, err)
	}
	return v
}

// csvCounts counts the services of a knx-datasets CSV export, if cached.
func csvCounts(t *testing.T, man *Manifest, file string) *Counts {
	t.Helper()
	for _, o := range man.Oracles {
		if o.For != file {
			continue
		}
		r, err := os.Open(filepath.Join(CacheDir(), filepath.FromSlash(o.File)))
		if err != nil {
			t.Logf("%s: %v (keeping the manifest's oracle counts)", o.File, err)
			return nil
		}
		defer func() { _ = r.Close() }()
		c := &Counts{Tool: "knx-datasets CSV (" + o.Name + ")", Services: map[string]int{}}
		if err := ReadCSV(r, func(row CSVRow) error { c.Services[CSVService(row.Info)]++; return nil }); err != nil {
			t.Fatal(err)
		}
		return c
	}
	return nil
}
