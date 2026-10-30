// SPDX-License-Identifier: MIT

// Command node is go-knx's adapter for the knx-interop matrix: it
// implements the knx-interop container contract (version 1.4) directly on
// the go-knx library, built from this repository's sources. `make
// interop-matrix` builds it into an image and runs knx-interop's matrix
// with it (--adapter goknx=IMAGE), so go-knx is tested in the Docker
// network against the third-party stacks, unreleased changes included.
// knx-interop itself does not depend on go-knx.
//
//	node capabilities
//	node server [--routing] [--name NAME] [--secure] [--tool-access]
//	node client OP [--target H] [--port P] [--nat] [--routing] [--tcp]
//	               [--secure] [--user N] [--udp] [--object T] [--pid P]
//	               [--group G] [--dpt D] [--value V] [--data HEX]
//	               [--count N] [--timeout SECONDS] [--device IA]
//	               [--start N] [--connected] [--tool-access]
//
// Each client operation prints one result document as the last line of
// stdout and exits 0 (pass), 1 (fail) or 3 (unsupported).
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/devmgmt"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/dpt"
	"github.com/otfabric/go-knx/keyring"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/routing"
	"github.com/otfabric/go-knx/secure"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

const (
	impl       = "go-knx"
	secureDir  = "/adapter/common/secure"
	serverIA   = "1.1.0"
	deviceIA   = "1.1.1"
	ifaceName  = "eth0"
	schemaVers = "1.0"
)

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/otfabric/go-knx" {
				return d.Version
			}
		}
		if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			return bi.Main.Version
		}
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return "source " + s.Value[:12]
			}
		}
	}
	return "source"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: node capabilities|server|client OP ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "capabilities":
		capabilities()
	case "server":
		os.Exit(runServer(os.Args[2:]))
	case "client":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: node client OP ...")
			os.Exit(2)
		}
		os.Exit(runClient(os.Args[2], os.Args[3:]))
	default:
		fmt.Fprintln(os.Stderr, "usage: node capabilities|server|client OP ...")
		os.Exit(2)
	}
}

func capabilities() {
	doc := map[string]any{
		"schemaVersion":  schemaVers,
		"implementation": impl,
		"version":        version(),
		"roles":          []string{"server", "client"},
		"features": map[string]any{
			"discover": true, "describe": true, "tunnel": true, "routing": true, "nat": true, "answer": true,
			"tcp": true, "property": true, "busmonitor": true,
			"secure": true, "dataSecure": true, "secureUdp": true, "surrogate": true,
			"remoteProperty": true, "toolAccess": true,
			"server": map[string]bool{"tcp": true, "property": true, "busmonitor": true, "secure": true, "secureUdp": true, "secureRouting": true,
				"remoteProperty": true, "toolAccess": true},
		},
		"notes": "go-knx's own adapter, built from its sources (go-knx/interop/node). The server is a simulator: busmonitor connections coexist with tunnels.",
	}
	b, _ := json.Marshal(doc)
	fmt.Println(string(b))
}

// args are the contract's options.
type args struct {
	target, group, dptID, value, data string
	port, object, pid, count, user    int
	timeout                           float64
	nat, routing, tcp, secure, udp    bool
	name                              string
	device                            string
	start                             int
	connected, toolAccess             bool
}

func parse(fs *flag.FlagSet, a *args, argv []string) error {
	fs.StringVar(&a.target, "target", "", "")
	fs.IntVar(&a.port, "port", knxnetip.Port, "")
	fs.BoolVar(&a.nat, "nat", false, "")
	fs.BoolVar(&a.routing, "routing", false, "")
	fs.BoolVar(&a.tcp, "tcp", false, "")
	fs.BoolVar(&a.secure, "secure", false, "")
	fs.IntVar(&a.user, "user", 2, "")
	fs.BoolVar(&a.udp, "udp", false, "")
	fs.IntVar(&a.object, "object", 0, "")
	fs.IntVar(&a.pid, "pid", 11, "")
	fs.StringVar(&a.group, "group", "", "")
	fs.StringVar(&a.dptID, "dpt", "", "")
	fs.StringVar(&a.value, "value", "", "")
	fs.StringVar(&a.data, "data", "", "")
	fs.IntVar(&a.count, "count", 1, "")
	fs.Float64Var(&a.timeout, "timeout", 5, "")
	fs.StringVar(&a.name, "name", "knx-interop", "")
	fs.StringVar(&a.device, "device", serverIA, "")
	fs.IntVar(&a.start, "start", 1, "")
	fs.BoolVar(&a.connected, "connected", false, "")
	fs.BoolVar(&a.toolAccess, "tool-access", false, "")
	return fs.Parse(argv)
}

// profile is the knx-interop KNX Secure test profile (public test values).
type profile struct {
	KeyringFile     string `json:"keyring"`
	KeyringPassword string `json:"keyringPassword"`
	Host            string `json:"host"`
	DevicePassword  string `json:"devicePassword"`
	kr              *keyring.Keyring
}

func loadProfile() (*profile, error) {
	b, err := os.ReadFile(secureDir + "/profile.json")
	if err != nil {
		return nil, err
	}
	var p profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.kr, err = keyring.LoadFile(secureDir+"/"+p.KeyringFile, p.KeyringPassword); err != nil {
		return nil, err
	}
	return &p, nil
}

// credentials of a profile user: 1 is the host's management password.
func (p *profile) credentials(user int) (secure.Credentials, error) {
	if user == 1 {
		d := p.kr.Device(knx.MustParseIndividualAddress(p.Host))
		if d == nil {
			return secure.Credentials{}, errors.New("no host device in the profile")
		}
		return secure.NewCredentials(1, d.ManagementPassword, p.DevicePassword)
	}
	for _, itf := range p.kr.Interfaces {
		if int(itf.UserID) == user {
			return itf.Credentials()
		}
	}
	return secure.Credentials{}, fmt.Errorf("no user %d in the profile", user)
}

// --- server ---------------------------------------------------------

func runServer(argv []string) int {
	var a args
	if err := parse(flag.NewFlagSet("server", flag.ContinueOnError), &a, argv); err != nil {
		return 2
	}
	var tunnels []knx.IndividualAddress
	for i := 10; i < 18; i++ {
		tunnels = append(tunnels, knx.MustParseIndividualAddress(fmt.Sprintf("1.1.%d", i)))
	}
	name := a.name
	if len(name) > 30 {
		name = name[:30]
	}
	opts := []server.Option{server.WithListenAddr(fmt.Sprintf("0.0.0.0:%d", knxnetip.Port)), server.WithName(name),
		server.WithIndividualAddress(knx.MustParseIndividualAddress(serverIA)), server.WithTunnelAddresses(tunnels...),
		server.WithConcurrentBusmonitor(true), server.WithInterface(ifaceName)}
	if a.routing {
		opts = append(opts, server.WithRouting(true))
	}
	if a.toolAccess {
		// The server's device management, secured with its tool key.
		p, err := loadProfile()
		if err != nil {
			fmt.Fprintln(os.Stderr, "profile:", err)
			return 1
		}
		d := p.kr.Device(knx.MustParseIndividualAddress(serverIA))
		if d == nil || !d.HasToolKey {
			fmt.Fprintln(os.Stderr, "profile: no tool key of", serverIA)
			return 1
		}
		opts = append(opts, server.WithToolKey(datasecure.Key(d.ToolKey)))
	}
	if a.secure {
		p, err := loadProfile()
		if err != nil {
			fmt.Fprintln(os.Stderr, "profile:", err)
			return 1
		}
		host := knx.MustParseIndividualAddress(p.Host)
		users := map[uint8]server.SecureUser{}
		for _, itf := range p.kr.Tunnels(host) {
			k, err := secure.UserPasswordKey(itf.Password)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			users[itf.UserID] = server.SecureUser{Key: k, Address: itf.IndividualAddress}
		}
		if d := p.kr.Device(host); d != nil {
			k, _ := secure.UserPasswordKey(d.ManagementPassword)
			users[1] = server.SecureUser{Key: k}
		}
		dev, err := secure.DeviceAuthenticationCode(p.DevicePassword)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		opts = append(opts, server.WithSecure(dev, users))
		if a.routing {
			if key, latency, ok := p.kr.BackboneKey(); ok {
				opts = append(opts, server.WithSecureRouting(key, latency))
			}
		}
	}
	s, err := server.New(opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	d := device.New("virtual", knx.MustParseIndividualAddress(deviceIA))
	for _, o := range []struct{ group, dpt, value string }{
		{"1/0/1", "1.001", "off"}, {"1/0/2", "9.001", "21.5"}, {"1/0/3", "5.001", "50"},
		{"1/0/4", "14.056", "1234.5"}, {"1/0/5", "16.000", "interop"},
	} {
		obj, err := device.NewGroupObject(o.group, o.dpt, "CRWU", o.group)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if v, err := obj.Type.Parse(o.value); err == nil {
			_ = obj.Set(v)
		}
		d.Add(obj)
	}
	s.AddDevice(d)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := s.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "READY")
	<-ctx.Done()
	_ = s.Close()
	return 0
}

// --- client ---------------------------------------------------------

type result struct {
	op    string
	start time.Time
}

func (r result) finish(status string, data map[string]any, err error) int {
	if data == nil {
		data = map[string]any{}
	}
	doc := map[string]any{"schemaVersion": schemaVers, "implementation": impl, "version": version(), "op": r.op,
		"status": status, "durationMs": time.Since(r.start).Milliseconds(), "data": data}
	if err != nil {
		doc["error"] = err.Error()
	}
	b, _ := json.Marshal(doc)
	fmt.Println(string(b))
	switch status {
	case "pass":
		return 0
	case "unsupported":
		return 3
	}
	return 1
}

func ready() { fmt.Fprintln(os.Stderr, "READY") }

func (a *args) endpoint() string { return fmt.Sprintf("%s:%d", a.target, a.port) }

func (a *args) wait() time.Duration { return time.Duration(a.timeout * float64(time.Second)) }

// tunnelOptions are the options of a tunnel to the target.
func (a *args) tunnelOptions(p *profile) ([]tunnel.Option, error) {
	opts := []tunnel.Option{tunnel.WithConnectTimeout(a.wait() + 5*time.Second)}
	if a.secure {
		c, err := p.credentials(a.user)
		if err != nil {
			return nil, err
		}
		opts = append(opts, tunnel.WithSecure(c))
		if a.udp {
			opts = append(opts, tunnel.WithUDP())
		}
		return opts, nil
	}
	if a.tcp {
		return append(opts, tunnel.WithTCP()), nil
	}
	return append(opts, tunnel.WithNAT(a.nat)), nil
}

// link opens the client of a group operation: a tunnel to the target or
// routing, with the profile's security when --secure.
func (a *args) link(ctx context.Context, p *profile) (*client.Client, error) {
	var copts []client.Option
	if a.secure {
		t, err := p.kr.DataSecure(0)
		if err != nil {
			return nil, err
		}
		copts = append(copts, client.WithDataSecure(t))
	}
	if a.routing {
		ropts := []routing.Option{routing.WithInterface(ifaceName), routing.WithLoopback(true)}
		if a.secure {
			if key, latency, ok := p.kr.BackboneKey(); ok {
				ropts = append(ropts, routing.WithSecure(key, latency))
			}
		}
		return client.ListenRouting(ctx, ropts, copts...)
	}
	topts, err := a.tunnelOptions(p)
	if err != nil {
		return nil, err
	}
	return client.DialTunnel(ctx, a.endpoint(), topts, copts...)
}

func serviceName(s apdu.APCI) string {
	switch s {
	case apdu.GroupValueReadService:
		return "read"
	case apdu.GroupValueResponseService:
		return "response"
	case apdu.GroupValueWriteService:
		return "write"
	default:
		return s.String()
	}
}

func runClient(op string, argv []string) int {
	r := result{op: op, start: time.Now()}
	var a args
	if err := parse(flag.NewFlagSet(op, flag.ContinueOnError), &a, argv); err != nil {
		return r.finish("fail", nil, err)
	}
	var p *profile
	if a.secure || a.toolAccess {
		var err error
		if p, err = loadProfile(); err != nil {
			return r.finish("fail", nil, fmt.Errorf("profile: %w", err))
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	data, err := do(ctx, op, &a, p)
	switch {
	case errors.Is(err, errUnsupported):
		return r.finish("unsupported", data, err)
	case err != nil:
		return r.finish("fail", data, err)
	}
	return r.finish("pass", data, nil)
}

var errUnsupported = errors.New("unsupported")

func do(ctx context.Context, op string, a *args, p *profile) (map[string]any, error) {
	switch op {
	case "discover":
		rs, err := discovery.Search(ctx, discovery.WithInterface(ifaceName), discovery.WithTimeout(a.wait()))
		if err != nil {
			return nil, err
		}
		devs := []map[string]string{}
		for _, x := range rs {
			d := x.Device()
			devs = append(devs, map[string]string{"endpoint": x.Endpoint().String(), "name": d.Name, "address": d.Address.String()})
		}
		return map[string]any{"devices": devs}, nil
	case "describe":
		dibs, err := discovery.Describe(ctx, a.endpoint(), discovery.WithNAT(a.nat), discovery.WithTimeout(a.wait()))
		if err != nil {
			return nil, err
		}
		d, _ := dibs.DeviceInfo()
		f, _ := dibs.SupportedServices()
		services := map[string]int{}
		for _, s := range f.Families {
			services[s.ID.String()] = int(s.Version)
		}
		return map[string]any{"name": d.Name, "address": d.Address.String(), "services": services}, nil
	case "connect":
		opts, err := a.tunnelOptions(p)
		if err != nil {
			return nil, err
		}
		c, err := tunnel.Dial(ctx, a.endpoint(), opts...)
		if err != nil {
			return nil, err
		}
		defer func() { _ = c.Close() }()
		return map[string]any{"channel": c.Channel(), "address": c.IndividualAddress().String()}, nil
	case "write":
		return write(ctx, a, p)
	case "read":
		return read(ctx, a, p)
	case "monitor":
		return monitor(ctx, a, p)
	case "answer":
		return answer(ctx, a, p)
	case "property":
		opts, err := a.tunnelOptions(p)
		if err != nil {
			return nil, err
		}
		c, err := devmgmt.Dial(ctx, a.endpoint(), opts...)
		if err != nil {
			return nil, err
		}
		defer func() { _ = c.Close() }()
		b, err := c.PropRead(ctx, uint16(a.object), 1, uint8(a.pid), 1, 1)
		if err != nil {
			return nil, err
		}
		return map[string]any{"data": strings.ToUpper(hex.EncodeToString(b))}, nil
	case "busmonitor":
		return busmonitor(ctx, a, p)
	case "remote-property":
		return remoteProperty(ctx, a, p)
	}
	return nil, fmt.Errorf("%w: operation %q", errUnsupported, op)
}

func groupValue(a *args) (*dpt.Type, any, apdu.GroupValue, error) {
	t, err := dpt.Lookup(a.dptID)
	if err != nil {
		return nil, nil, apdu.GroupValue{}, err
	}
	v, err := t.Parse(a.value)
	if err != nil {
		return nil, nil, apdu.GroupValue{}, err
	}
	b, err := t.Encode(v)
	if err != nil {
		return nil, nil, apdu.GroupValue{}, err
	}
	return t, v, apdu.GroupValue{Data: b, Small: t.Small()}, nil
}

func write(ctx context.Context, a *args, p *profile) (map[string]any, error) {
	g, err := knx.ParseGroupAddress(a.group)
	if err != nil {
		return nil, err
	}
	_, v, gv, err := groupValue(a)
	if err != nil {
		return nil, err
	}
	c, err := a.link(ctx, p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if err := c.GroupWrite(ctx, g, v, client.WithDPT(a.dptID)); err != nil {
		return nil, err
	}
	return map[string]any{"data": strings.ToUpper(hex.EncodeToString(gv.Data))}, nil
}

func read(ctx context.Context, a *args, p *profile) (map[string]any, error) {
	g, err := knx.ParseGroupAddress(a.group)
	if err != nil {
		return nil, err
	}
	c, err := a.link(ctx, p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	rctx, cancel := context.WithTimeout(ctx, a.wait())
	defer cancel()
	var ropts []client.WriteOption
	if a.dptID != "" {
		ropts = append(ropts, client.WithDPT(a.dptID))
	}
	resp, err := c.GroupRead(rctx, g, ropts...)
	if err != nil {
		return nil, err
	}
	return map[string]any{"source": resp.Source.String(), "data": strings.ToUpper(hex.EncodeToString(resp.Value.Data)), "value": resp.Decoded}, nil
}

func monitor(ctx context.Context, a *args, p *profile) (map[string]any, error) {
	c, err := a.link(ctx, p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	var mu sync.Mutex
	tel := []map[string]string{}
	done := make(chan struct{})
	remove := c.OnTelegram(func(t client.Telegram) {
		mu.Lock()
		defer mu.Unlock()
		tel = append(tel, map[string]string{"source": t.Source.String(), "group": t.Group.String(), "service": serviceName(t.Service),
			"data": strings.ToUpper(hex.EncodeToString(t.Value.Data))})
		if len(tel) == a.count {
			close(done)
		}
	})
	defer remove()
	ready()
	select {
	case <-done:
	case <-time.After(a.wait()):
	case <-ctx.Done():
	}
	mu.Lock()
	defer mu.Unlock()
	data := map[string]any{"telegrams": tel}
	if len(tel) < a.count {
		return data, fmt.Errorf("received %d of %d telegrams", len(tel), a.count)
	}
	return data, nil
}

func answer(ctx context.Context, a *args, p *profile) (map[string]any, error) {
	g, err := knx.ParseGroupAddress(a.group)
	if err != nil {
		return nil, err
	}
	_, v, _, err := groupValue(a)
	if err != nil {
		return nil, err
	}
	c, err := a.link(ctx, p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	reads := make(chan struct{}, 16)
	remove := c.OnTelegram(func(t client.Telegram) {
		if t.Group == g && t.Service == apdu.GroupValueReadService {
			select {
			case reads <- struct{}{}:
			default:
			}
		}
	})
	defer remove()
	ready()
	answered := 0
	deadline := time.After(a.wait())
	for answered < a.count {
		select {
		case <-reads:
			if err := c.GroupRespond(ctx, g, v, client.WithDPT(a.dptID)); err != nil {
				return map[string]any{"answered": answered}, err
			}
			answered++
		case <-deadline:
			return map[string]any{"answered": answered}, nil
		case <-ctx.Done():
			return map[string]any{"answered": answered}, nil
		}
	}
	// Let the last response leave before the tunnel closes.
	time.Sleep(300 * time.Millisecond)
	return map[string]any{"answered": answered}, nil
}

func busmonitor(ctx context.Context, a *args, p *profile) (map[string]any, error) {
	opts, err := a.tunnelOptions(p)
	if err != nil {
		return nil, err
	}
	c, err := tunnel.Dial(ctx, a.endpoint(), append(opts, tunnel.WithLayer(knxnetip.TunnelBusmonitor))...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	ready()
	frames := []map[string]string{}
	rctx, cancel := context.WithTimeout(ctx, a.wait())
	defer cancel()
	for len(frames) < a.count {
		f, err := c.Receive(rctx)
		if err != nil {
			break
		}
		raw, ok := f.(*cemi.Raw)
		if !ok || raw.MsgCode != cemi.LBusmonInd {
			continue
		}
		rec := map[string]string{"raw": strings.ToUpper(hex.EncodeToString(raw.Data))}
		if ld, err := cemi.ParseTP1(raw.Data); err == nil {
			rec["source"] = ld.Source.String()
			rec["destination"] = ld.DestinationString()
		}
		frames = append(frames, rec)
	}
	data := map[string]any{"frames": frames}
	if len(frames) < a.count {
		return data, fmt.Errorf("received %d of %d frames", len(frames), a.count)
	}
	return data, nil
}

// remoteProperty reads (or with --data writes) a property of a device
// through a tunnel to the target, with the remote property services:
// --object is the interface object type, resolved to its index through
// the device's interface object list; --connected uses a transport
// connection; --tool-access secures the access with the device's tool
// key from the profile.
func remoteProperty(ctx context.Context, a *args, p *profile) (map[string]any, error) {
	dev, err := knx.ParseIndividualAddress(a.device)
	if err != nil {
		return nil, err
	}
	topts, err := a.tunnelOptions(p)
	if err != nil {
		return nil, err
	}
	// No Data Secure table: the access is secured only with --tool-access.
	c, err := client.DialTunnel(ctx, a.endpoint(), topts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	var dopts []client.DeviceOption
	if a.connected {
		dopts = append(dopts, client.Connected())
	}
	if a.toolAccess {
		d := p.kr.Device(dev)
		if d == nil || !d.HasToolKey {
			return nil, fmt.Errorf("no tool key of %s in the profile", dev)
		}
		dopts = append(dopts, client.WithToolKey(datasecure.Key(d.ToolKey)))
	}
	d := c.Device(dev, dopts...)
	defer func() { _ = d.Close() }()
	rctx, cancel := context.WithTimeout(ctx, a.wait()+5*time.Second)
	defer cancel()
	index, err := objectIndex(rctx, d, uint16(a.object))
	if err != nil {
		return nil, err
	}
	var b []byte
	if a.data != "" {
		v, err := hex.DecodeString(a.data)
		if err != nil {
			return nil, err
		}
		b, err = d.PropertyWrite(rctx, index, uint8(a.pid), uint16(a.start), uint8(a.count), v)
		if err != nil {
			return nil, err
		}
	} else if b, err = d.PropertyRead(rctx, index, uint8(a.pid), uint16(a.start), uint8(a.count)); err != nil {
		return nil, err
	}
	return map[string]any{"data": strings.ToUpper(hex.EncodeToString(b)), "object": index}, nil
}

// objectIndex finds the index of an interface object type in the
// device's interface object list (device object, PID 71).
func objectIndex(ctx context.Context, d *client.Device, objType uint16) (uint8, error) {
	if objType == 0 {
		return 0, nil
	}
	n, err := d.PropertyElements(ctx, 0, 71)
	if err != nil {
		return 0, fmt.Errorf("interface object list: %w", err)
	}
	for start := 1; start <= n; start += 15 {
		count := min(15, n-start+1)
		b, err := d.PropertyRead(ctx, 0, 71, uint16(start), uint8(count))
		if err != nil {
			return 0, fmt.Errorf("interface object list: %w", err)
		}
		for i := 0; i+1 < len(b); i += 2 {
			if uint16(b[i])<<8|uint16(b[i+1]) == objType {
				return uint8(start - 1 + i/2), nil
			}
		}
	}
	return 0, fmt.Errorf("no interface object of type %d on %s", objType, d.Address())
}
