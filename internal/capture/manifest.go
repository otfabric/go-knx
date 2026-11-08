// SPDX-License-Identifier: MIT

package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Manifest lists every capture examined: provenance, evidence class, what
// go-knx makes of it and what an independent decoder (Wireshark, or the
// dataset authors' own decode) makes of it. TestCorpus re-derives the
// go-knx counts from the committed captures; make captures-generate
// rewrites them, and the oracle counts, from the captures and tshark.
type Manifest struct {
	Generated string   `json:"generated"`
	Wireshark string   `json:"wireshark"`
	Sources   []Source `json:"sources"`
	Files     []Entry  `json:"files"`
	// Oracles are files that are not captures but independent decodes of
	// one: the knx-datasets CSV exports, fetched by make captures-fetch.
	Oracles []Oracle `json:"oracles"`
	// Skipped are files of the sources that are not committed, and why.
	Skipped []Skipped `json:"skipped,omitempty"`
}

// Source is one place captures were taken from.
type Source struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Revision string `json:"revision"`
	Fetched  string `json:"fetched"`
	Terms    string `json:"terms"`
	Origin   string `json:"origin"`
}

// Entry is one committed capture file.
type Entry struct {
	Source     string   `json:"source"`
	Name       string   `json:"name"` // the original file name
	File       string   `json:"file"` // under testdata/captures
	URL        string   `json:"url"`
	SHA256     string   `json:"sha256"`
	Size       int64    `json:"size"`
	Format     string   `json:"format"`
	Transport  string   `json:"transport"` // "tp1", "knxnetip"
	Class      string   `json:"class"`
	ClassBasis string   `json:"class_basis"`
	Devices    []string `json:"devices,omitempty"`
	Privacy    string   `json:"privacy"`
	Stats      Stats    `json:"stats"`
	Oracle     *Counts  `json:"oracle,omitempty"`
}

// Counts are an independent decoder's counts for one capture.
type Counts struct {
	Tool string `json:"tool"`
	// Services counts KNXnet/IP service type codes ("0x0530") or, for a
	// TP1 capture, transport and application services.
	Services map[string]int `json:"services"`
	// Malformed counts frames the decoder marks malformed.
	Malformed int `json:"malformed"`
	// CEMICodes counts cEMI message codes ("0x29").
	CEMICodes map[string]int `json:"cemi_codes,omitempty"`
}

// Oracle is an independent decode of a capture, kept in the cache.
type Oracle struct {
	For    string `json:"for"`  // the Entry.File it decodes
	Name   string `json:"name"` // original file name
	File   string `json:"file"` // path under the cache
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Skipped is a file of a source that is not committed.
type Skipped struct {
	Source string `json:"source"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	Reason string `json:"reason"`
}

// Dir is testdata/captures.
func Dir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "testdata", "captures")
}

// CacheDir is where make captures-fetch puts the files that are not
// committed: KNX_CAPTURE_CACHE, else testdata/captures/cache (git-ignored).
func CacheDir() string {
	if d := os.Getenv("KNX_CAPTURE_CACHE"); d != "" {
		return d
	}
	return filepath.Join(Dir(), "cache")
}

// LoadManifest reads testdata/captures/manifest.json.
func LoadManifest() (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(Dir(), "manifest.json"))
	if err != nil {
		return nil, err
	}
	m := &Manifest{}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, err
	}
	return m, nil
}

// Load reads a committed capture by its path under testdata/captures.
func Load(rel string) (*File, error) { return ReadFile(filepath.Join(Dir(), filepath.FromSlash(rel))) }
