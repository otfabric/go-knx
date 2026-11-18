// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// lock is the content of dpt/masterdata.lock: one "key value" pair per
// line, # starts a comment.
type lock struct {
	URL     string
	Schema  int
	Version int
	SHA256  string
}

func parseLock(b []byte) (lock, error) {
	var lk lock
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		val = strings.TrimSpace(val)
		if !ok || val == "" {
			return lock{}, fmt.Errorf("line %d: want \"key value\"", n)
		}
		if seen[key] {
			return lock{}, fmt.Errorf("line %d: %s given twice", n, key)
		}
		seen[key] = true
		var err error
		switch key {
		case "url":
			if !strings.HasPrefix(val, "https://") {
				return lock{}, fmt.Errorf("line %d: url must be https", n)
			}
			lk.URL = val
		case "schema":
			lk.Schema, err = strconv.Atoi(val)
		case "version":
			lk.Version, err = strconv.Atoi(val)
		case "sha256":
			if b, herr := hex.DecodeString(val); herr != nil || len(b) != sha256.Size {
				err = errors.New("not a SHA-256 in hex")
			}
			lk.SHA256 = strings.ToLower(val)
		default:
			return lock{}, fmt.Errorf("line %d: unknown key %q", n, key)
		}
		if err != nil {
			return lock{}, fmt.Errorf("line %d: %s: %w", n, key, err)
		}
	}
	for _, k := range []string{"url", "schema", "version", "sha256"} {
		if !seen[k] {
			return lock{}, fmt.Errorf("%s is missing", k)
		}
	}
	return lk, nil
}

// verify checks the downloaded file against the lock: its SHA-256, and
// the schema and version it declares.
func (lk lock) verify(data []byte, md *masterData) error {
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != lk.SHA256 {
		return fmt.Errorf("sha256 %s, the lock has %s (upstream has changed: make masterdata-update)", got, lk.SHA256)
	}
	if md.Schema != lk.Schema {
		return fmt.Errorf("schema %d, the lock has %d", md.Schema, lk.Schema)
	}
	if md.Version != lk.Version {
		return fmt.Errorf("version %d, the lock has %d", md.Version, lk.Version)
	}
	return nil
}
