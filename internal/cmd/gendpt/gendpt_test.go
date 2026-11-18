// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sample is a master data file written for these tests: the structure of
// knx_master.xml with made-up types.
const sample = `<?xml version="1.0" encoding="UTF-8"?>
<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="7">
    <DatapointTypes>
      <DatapointType Id="DPT-900" Number="900" Name="900.xxx" Text="test" SizeInBit="16">
        <DatapointSubtypes>
          <DatapointSubtype Id="DPST-900-2" Number="2" Name="DPT_Second" Text="second">
            <Format>
              <RefType RefId="DPST-900-1_F-1" />
              <Enumeration Id="DPST-900-2_F-2" Width="8" Name="mode">
                <EnumValue Id="x" Value="0" Text="a" />
                <EnumValue Id="y" Value="1" Text="b &amp; &quot;c&quot;" />
              </Enumeration>
            </Format>
          </DatapointSubtype>
          <DatapointSubtype Id="DPST-900-1" Number="1" Name="DPT_First" Text="first">
            <Format>
              <Bit Id="DPST-900-1_F-1" Cleared="Off" Set="On" Name="flag" />
              <Reserved Width="3" />
              <UnsignedInteger Id="f3" Width="4" Unit="%" Coefficient="0.3921566" MinInclusive="0" MaxInclusive="15" />
              <SignedInteger Id="f4" Width="8" MinInclusive="-9223372036854775808" MaxInclusive="9223372036854775807" />
            </Format>
          </DatapointSubtype>
        </DatapointSubtypes>
      </DatapointType>
      <DatapointType Id="DPT-901" Number="901" Name="901.xxx" Text="float" SizeInBit="32">
        <DatapointSubtypes>
          <DatapointSubtype Id="DPST-901-0" Number="0" Name="DPT_F" Text="f">
            <Format>
              <Float Id="f5" Width="32" Unit="W" MinValue="-1.5" MaxValue="2e3" />
            </Format>
          </DatapointSubtype>
          <DatapointSubtype Id="DPST-901-3" Number="3" Name="DPT_S" Text="s">
            <Format>
              <String Id="f6" Width="32" Encoding="us-ascii" />
            </Format>
          </DatapointSubtype>
          <DatapointSubtype Id="DPST-901-4" Number="4" Name="DPT_V" Text="v">
            <Format>
              <String Id="f7" VariableLength="true" NullTerminated="true" Encoding="utf-8" />
            </Format>
          </DatapointSubtype>
          <DatapointSubtype Id="DPST-901-5" Number="5" Name="DPT_None" Text="none" />
        </DatapointSubtypes>
      </DatapointType>
    </DatapointTypes>
  </MasterData>
</KNX>
`

func lockFor(data []byte, schema, version int) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("# test\n\nurl https://example.invalid/knx_master.xml\nschema %d\nversion %d\nsha256 %s\n",
		schema, version, hex.EncodeToString(sum[:]))
}

func TestParseMasterData(t *testing.T) {
	md, err := parseMasterData([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if md.Schema != 23 || md.Version != 7 || len(md.Subtypes) != 6 {
		t.Fatalf("schema %d version %d, %d subtypes", md.Schema, md.Version, len(md.Subtypes))
	}
	first, second := md.Subtypes[0], md.Subtypes[1]
	if first.Sub != 1 || second.Sub != 2 {
		t.Fatalf("not sorted: %d, %d", first.Sub, second.Sub)
	}
	if len(first.Fields) != 4 || first.Fields[0].Kind != "mdBit" || first.Fields[0].Width != 1 || first.Fields[1].Kind != "mdReserved" {
		t.Errorf("first: %+v", first.Fields)
	}
	if f := first.Fields[2]; !f.HasRange || f.Max != 15 || f.Coefficient != 0.3921566 || f.Unit != "%" {
		t.Errorf("unsigned: %+v", f)
	}
	if f := first.Fields[3]; !f.HasRange || f.Min != -9223372036854775808 {
		t.Errorf("signed: %+v", f)
	}
	// The reference to a field of a later subtype is resolved.
	if f := second.Fields[0]; f.Kind != "mdBit" || f.Set != "On" {
		t.Errorf("RefType: %+v", f)
	}
	if f := second.Fields[1]; len(f.Enum) != 2 || f.Enum[1].Text != `b & "c"` {
		t.Errorf("enum: %+v", f)
	}
	if f := md.Subtypes[2].Fields[0]; f.Kind != "mdFloat" || !f.HasRange || f.Min != -1.5 || f.Max != 2000 {
		t.Errorf("float: %+v", f)
	}
	if f := md.Subtypes[4].Fields[0]; f.Kind != "mdString" || f.Encoding != "utf-8" {
		t.Errorf("variable string: %+v", f)
	}
	if len(md.Subtypes[5].Fields) != 0 {
		t.Errorf("no format: %+v", md.Subtypes[5].Fields)
	}
}

func TestParseMasterDataErrors(t *testing.T) {
	for _, tc := range []struct{ name, old, new, want string }{
		{"not XML", "<KNX", "<<", "XML"},
		{"root", `<KNX xmlns="http://knx.org/xml/project/23">`, `<KNX xmlns="urn:other">`, "root element"},
		{"schema", `project/23"`, `project/x"`, "no schema number"},
		{"version", `Version="7"`, `Version="v7"`, "Version"},
		{"type number", `Number="900"`, `Number="x"`, "datapoint type"},
		{"size", `SizeInBit="16"`, `SizeInBit="0"`, "SizeInBit"},
		{"sub number", `Number="2"`, `Number="70000"`, "subtype"},
		{"element", `<Reserved Width="3" />`, `<Packed Width="3" />`, "unknown format element Packed"},
		{"attribute", `<Reserved Width="3" />`, `<Reserved Width="3" Offset="1" />`, "unknown attribute Offset"},
		{"width", `<Reserved Width="3" />`, `<Reserved Width="0" />`, "Width"},
		{"no width", `<Reserved Width="3" />`, `<Reserved />`, "without Width"},
		{"coefficient", `Coefficient="0.3921566"`, `Coefficient="-1"`, "Coefficient"},
		{"range", `MinInclusive="0" MaxInclusive="15"`, `MinInclusive="9" MaxInclusive="1"`, "range"},
		{"infinite", `MaxValue="2e3"`, `MaxValue="1e999"`, "range"},
		{"not a number", `MaxValue="2e3"`, `MaxValue="NaN"`, "range"},
		{"infinity", `MinValue="-1.5"`, `MinValue="-Inf"`, "range"},
		{"enum value", `Value="1"`, `Value="-1"`, "EnumValue"},
		{"ref id", `<RefType RefId="DPST-900-1_F-1" />`, `<RefType />`, "without RefId"},
		{"ref", `RefId="DPST-900-1_F-1"`, `RefId="nowhere"`, "no such field"},
		{"duplicate", `Number="2" Name="DPT_Second"`, `Number="1" Name="DPT_Second"`, "given twice"},
	} {
		in := strings.Replace(sample, tc.old, tc.new, 1)
		if in == sample {
			t.Fatalf("%s: %q not in the sample", tc.name, tc.old)
		}
		_, err := parseMasterData([]byte(in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	empty := `<KNX xmlns="http://knx.org/xml/project/23"><MasterData Version="1"/></KNX>`
	if _, err := parseMasterData([]byte(empty)); err == nil || !strings.Contains(err.Error(), "no datapoint types") {
		t.Errorf("empty: %v", err)
	}
}

func TestLock(t *testing.T) {
	data := []byte(sample)
	lk, err := parseLock([]byte(lockFor(data, 23, 7)))
	if err != nil {
		t.Fatal(err)
	}
	md, _ := parseMasterData(data)
	if err := lk.verify(data, md); err != nil {
		t.Fatal(err)
	}
	if err := lk.verify(append(data, ' '), md); err == nil || !strings.Contains(err.Error(), "masterdata-update") {
		t.Errorf("other file: %v", err)
	}
	for _, tc := range []struct {
		lock lock
		want string
	}{
		{lock{SHA256: lk.SHA256, Schema: 22, Version: 7}, "schema"},
		{lock{SHA256: lk.SHA256, Schema: 23, Version: 8}, "version"},
	} {
		if err := tc.lock.verify(data, md); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", tc.lock, err, tc.want)
		}
	}
	good := lockFor(data, 23, 7)
	for _, tc := range []struct{ in, want string }{
		{"url\n", "key value"},
		{"url http://x\n", "https"},
		{"schema x\n", "schema"},
		{"version x\n", "version"},
		{"sha256 abcd\n", "SHA-256"},
		{"colour red\n", "unknown key"},
		{"url https://a\nurl https://b\n", "twice"},
		{"url https://a\n", "missing"},
	} {
		in := tc.in
		if tc.want != "missing" && tc.want != "twice" {
			in = tc.in + good
		}
		if _, err := parseLock([]byte(in)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.in, err, tc.want)
		}
	}
}

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	in, lockPath, out := filepath.Join(dir, "m.xml"), filepath.Join(dir, "m.lock"), filepath.Join(dir, "gen.go")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(in, sample)
	write(lockPath, lockFor([]byte(sample), 23, 7))
	var stderr bytes.Buffer
	if code := run([]string{"-in", in, "-lock", lockPath, "-out", out}, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	src, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"// Code generated by gendpt from the KNX master data. DO NOT EDIT.",
		"masterDataSchema  = 23",
		"masterDataVersion = 7",
		`{ID: ID{900, 1}, Name: "DPT_First", Text: "first", Bits: 16, Fields: []mdField{`,
		`{Kind: mdBit, Width: 1, Name: "flag", Cleared: "Off", Set: "On"},`,
		`{Kind: mdUnsigned, Width: 4, Unit: "%", Min: 0, Max: 15, HasRange: true, Coefficient: 0.3921566},`,
		`Enum: []mdEnumValue{{0, "a"}, {1, "b & \"c\""}}`,
		`{Kind: mdFloat, Width: 32, Unit: "W", Min: -1.5, Max: 2000, HasRange: true},`,
		`{Kind: mdString, Width: 32, Encoding: "us-ascii"},`,
		`{ID: ID{901, 5}, Name: "DPT_None", Text: "none", Bits: 32},`,
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("generated file lacks %s", want)
		}
	}

	// A lock for another file is refused and nothing is written.
	write(lockPath, lockFor([]byte("other"), 23, 7))
	os.Remove(out)
	if code := run([]string{"-in", in, "-lock", lockPath, "-out", out}, &stderr); code != 1 {
		t.Errorf("wrong lock: exit %d", code)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("written despite the wrong lock")
	}
	for _, args := range [][]string{
		{"-in", filepath.Join(dir, "missing.xml"), "-lock", lockPath, "-out", out},
		{"-in", in, "-lock", filepath.Join(dir, "missing.lock"), "-out", out},
	} {
		if code := run(args, &stderr); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	write(lockPath, "url x\n")
	if code := run([]string{"-in", in, "-lock", lockPath}, &stderr); code != 1 {
		t.Errorf("bad lock: exit %d", code)
	}
	write(lockPath, lockFor([]byte("<x/>"), 23, 7))
	write(in, "<x/>")
	if code := run([]string{"-in", in, "-lock", lockPath}, &stderr); code != 1 {
		t.Errorf("bad XML: exit %d", code)
	}
	for _, args := range [][]string{{}, {"-in", in, "extra"}, {"-nope"}} {
		if code := run(args, &stderr); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// A model that does not give valid Go (here a kind that is not an
// identifier) is refused by gofmt, and nothing is written.
func TestWriteRefusesInvalidSource(t *testing.T) {
	out := filepath.Join(t.TempDir(), "gen.go")
	md := &masterData{Schema: 23, Version: 1, Subtypes: []subtype{{Main: 1, Sub: 1, Bits: 1, Fields: []field{{Kind: "md Bit", Width: 1}}}}}
	if err := write(out, lock{URL: "https://x", SHA256: strings.Repeat("0", 64)}, md); err == nil {
		t.Fatal("invalid source formatted")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("written despite the error")
	}
}

// main exits with run's status: the binary is the test binary run again
// with GENDPT_MAIN set.
func TestMain(m *testing.M) {
	if os.Getenv("GENDPT_MAIN") == "1" {
		os.Args = []string{"gendpt"}
		main()
	}
	os.Exit(m.Run())
}

func TestMainExitStatus(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "GENDPT_MAIN=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 || !strings.Contains(stderr.String(), "usage: gendpt") {
		t.Fatalf("main without arguments: %v, stderr %q; want exit 2 and the usage", err, stderr.String())
	}
}
