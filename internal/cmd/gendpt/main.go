// SPDX-License-Identifier: MIT

// Command gendpt generates dpt/masterdata_gen.go from the KNX master data
// (knx_master.xml, published by the KNX Association for ETS at
// update.knx.org). The XML is not kept in the repository: dpt/masterdata.lock
// pins its URL, schema, version and SHA-256, and gendpt refuses a file that
// does not match the lock. Run it through make:
//
//	make generate           # download the pinned file and regenerate
//	make masterdata-update  # pin the newest published file and regenerate
//	make masterdata-check   # report what changed upstream (exit 1)
//
// Usage:
//
//	gendpt -in knx_master.xml -lock dpt/masterdata.lock -out dpt/masterdata_gen.go
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("gendpt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "the KNX master data (knx_master.xml)")
	lockPath := fs.String("lock", "dpt/masterdata.lock", "the lock file that pins the master data")
	out := fs.String("out", "dpt/masterdata_gen.go", "the Go file to write")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *in == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: gendpt -in knx_master.xml [-lock dpt/masterdata.lock] [-out dpt/masterdata_gen.go]")
		return 2
	}
	if err := generate(*in, *lockPath, *out); err != nil {
		fmt.Fprintln(stderr, "gendpt:", err)
		return 1
	}
	return 0
}

// generate checks the master data against the lock and writes the Go file.
func generate(in, lockPath, out string) error {
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	lockData, err := os.ReadFile(lockPath)
	if err != nil {
		return err
	}
	lk, err := parseLock(lockData)
	if err != nil {
		return fmt.Errorf("%s: %w", lockPath, err)
	}
	md, err := parseMasterData(data)
	if err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}
	if err := lk.verify(data, md); err != nil {
		return fmt.Errorf("%s does not match %s: %w", in, lockPath, err)
	}
	src, err := emit(lk, md)
	if err != nil {
		return err
	}
	return os.WriteFile(out, src, 0o644)
}
