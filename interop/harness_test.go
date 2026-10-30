// SPDX-License-Identifier: MIT

//go:build interop

// Package interop tests go-knx against independent KNX implementations
// packaged by otfabric/knx-interop: go-knx as the client of Calimero's and
// knxd's KNXnet/IP servers, and go-knx's server with Calimero, knxd and
// xknx as clients. The scenarios are unicast: the host reaches the
// containers through published UDP ports and the containers reach the host
// through host.docker.internal, with route back (NAT) endpoints, so the
// suite runs the same on Linux and macOS. Multicast scenarios (discovery,
// routing) run in knx-interop's matrix, inside one Docker network.
//
// Images: KNX_INTEROP_IMAGE_<ADAPTER> (for example
// KNX_INTEROP_IMAGE_XKNX=ghcr.io/otfabric/knx-interop-xknx:dev) overrides
// the pinned image of an adapter. KNX_REQUIRE_INTEROP=1 turns a missing
// Docker into a failure. KNX_INTEROP_REPORT=<file> writes the results as
// JSON.
package interop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// images are the knx-interop v0.3.0 adapter images. The MIT ones are
// published and pinned by digest; the ones with GPL binaries (Calimero,
// knxd) are never published: make interop-images builds them from the
// knx-interop v0.3.0 tag as :dev.
var images = map[string]string{
	"calimero-server": "ghcr.io/otfabric/knx-interop-calimero-server:dev",
	"calimero-tools":  "ghcr.io/otfabric/knx-interop-calimero-tools:dev",
	"knxd":            "ghcr.io/otfabric/knx-interop-knxd:dev",
	"xknx":            "ghcr.io/otfabric/knx-interop-xknx:0.3.0@sha256:d1a939e96c7fdf719027363be95ea5def6a81fcf12d0cc8d4762636428965247",
	"knxultimate":     "ghcr.io/otfabric/knx-interop-knxultimate:0.3.0@sha256:9f76d73914fdee7fcefae3c57e3adea300186a7df5e823c51a46653f7148d3f4",
}

func image(adapter string) string {
	key := "KNX_INTEROP_IMAGE_" + strings.ToUpper(strings.ReplaceAll(adapter, "-", "_"))
	if v := os.Getenv(key); v != "" {
		return v
	}
	return images[adapter]
}

func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "version").Run(); err != nil {
		if os.Getenv("KNX_REQUIRE_INTEROP") == "1" {
			t.Fatalf("docker is required: %v", err)
		}
		t.Skipf("docker not available: %v", err)
	}
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// result is one recorded outcome.
type result struct {
	Test     string `json:"test"`
	Peer     string `json:"peer"`
	Version  string `json:"peerVersion,omitempty"`
	Scenario string `json:"scenario"`
	Result   string `json:"result"`
	Detail   string `json:"detail,omitempty"`
}

var (
	resMu   sync.Mutex
	results []result
)

func record(t *testing.T, peer, scenario string, err error, detail string) {
	t.Helper()
	r := result{Test: t.Name(), Peer: peer, Version: versionOf(peer), Scenario: scenario, Result: "pass", Detail: detail}
	if err != nil {
		r.Result, r.Detail = "fail", err.Error()
		t.Errorf("%s / %s: %v", peer, scenario, err)
	}
	resMu.Lock()
	results = append(results, r)
	resMu.Unlock()
}

var versions sync.Map

func versionOf(adapter string) string {
	if v, ok := versions.Load(adapter); ok {
		return v.(string)
	}
	out, err := exec.Command("docker", "run", "--rm", image(adapter), "capabilities").Output()
	v := "unknown"
	if err == nil {
		var c struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(bytes.TrimSpace(out), &c) == nil {
			v = c.Version
		}
	}
	versions.Store(adapter, v)
	return v
}

func TestMain(m *testing.M) {
	code := m.Run()
	if f := os.Getenv("KNX_INTEROP_REPORT"); f != "" {
		b, _ := json.MarshalIndent(map[string]any{"schemaVersion": "1.0", "time": time.Now().UTC().Format(time.RFC3339), "results": results}, "", "  ")
		_ = os.WriteFile(f, append(b, '\n'), 0o644)
	}
	os.Exit(code)
}

// adapterDoc is the result document of the container contract.
type adapterDoc struct {
	Status string         `json:"status"`
	Data   map[string]any `json:"data"`
	Error  string         `json:"error"`
}

// runClient runs a client operation of an adapter and decodes its result.
func runClient(ctx context.Context, adapter string, extra []string, op string, args ...string) (adapterDoc, error) {
	cmd := append([]string{"run", "--rm"}, extra...)
	cmd = append(cmd, image(adapter), "client", op)
	cmd = append(cmd, args...)
	out, err := exec.CommandContext(ctx, "docker", cmd...).Output()
	var d adapterDoc
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if jerr := json.Unmarshal([]byte(lines[len(lines)-1]), &d); jerr != nil {
		return d, fmt.Errorf("%s %s: no result document (%v): %s", adapter, op, err, out)
	}
	if d.Status != "pass" {
		return d, fmt.Errorf("%s %s: %s: %s", adapter, op, d.Status, d.Error)
	}
	return d, nil
}

// background starts a long-running adapter operation and returns once it
// printed READY, with a function that waits for its result.
func background(t *testing.T, adapter string, extra []string, op string, args ...string) func() (adapterDoc, error) {
	t.Helper()
	name := fmt.Sprintf("goknx-interop-%d", time.Now().UnixNano())
	cmd := append([]string{"run", "--rm", "--name", name}, extra...)
	cmd = append(cmd, image(adapter), "client", op)
	cmd = append(cmd, args...)
	c := exec.Command("docker", cmd...)
	var stdout bytes.Buffer
	c.Stdout = &stdout
	pr, pw, _ := os.Pipe()
	c.Stderr = pw
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	ready := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		var acc []byte
		once := sync.Once{}
		for {
			n, err := pr.Read(buf)
			acc = append(acc, buf[:n]...)
			if bytes.Contains(acc, []byte("READY")) {
				once.Do(func() { close(ready) })
			}
			if err != nil {
				once.Do(func() { close(ready) })
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(60 * time.Second):
		_ = exec.Command("docker", "rm", "-f", name).Run()
		t.Fatalf("%s %s did not become ready", adapter, op)
	}
	time.Sleep(300 * time.Millisecond)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	return func() (adapterDoc, error) {
		done := make(chan error, 1)
		go func() { done <- c.Wait() }()
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			_ = exec.Command("docker", "rm", "-f", name).Run()
			<-done
		}
		var d adapterDoc
		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &d); err != nil {
			return d, fmt.Errorf("%s %s: no result document: %s", adapter, op, stdout.String())
		}
		if d.Status != "pass" {
			return d, fmt.Errorf("%s %s: %s: %s", adapter, op, d.Status, d.Error)
		}
		return d, nil
	}
}

func execDocker(args ...string) error { return exec.Command("docker", args...).Run() }
