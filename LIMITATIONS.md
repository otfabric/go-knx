# Limitations

What go-knx does not do, or does with restrictions. Feature status:
[docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md). Evidence:
[INTEROPERABILITY.md](INTEROPERABILITY.md).

## Certification and conformance

- **Nothing here is certified**: go-knx is not KNX certified and claims no
  conformance to the KNX standard
  ([docs/standards/CONFORMANCE.md](docs/standards/CONFORMANCE.md)).
- KNX IP Secure and KNX Data Secure are implemented from public sources and
  verified against xknx and Calimero; conformance to AN158/AN159 is not
  established.
- Passing the interop suites shows that go-knx and those stacks agree with
  each other, not that any of them conforms.
- No physical KNX IP interface or router has been tested live. Recorded
  traffic of physical devices is replayed instead
  ([testdata/captures](testdata/captures/README.md), class B): the KNXnet/IP
  sessions of an ABB IP-Router IPR/S and an ABB IPS/S2.1 with a test client
  (firmware unknown), and a KNX TP1 house installation whose device models
  are not documented.

## Not implemented

- KNX TP and RF media (TP1 frames are handled for busmonitor only), ETS
  project import, KNX IoT.
- Device-to-device link keys and secure commissioning (FDSK).
- Remote device management: no memory, restart or ADC services
  (`mgmt.Responder` acknowledges A_Memory_Read and A_ADC_Read in a
  connection and does not answer them; the recorded devices do).
- cEMI transport layer messages (T_Data_Connected, T_Data_Individual:
  message codes 0x41, 0x89, 0x4A, 0x94), which ABB IP devices use for local
  management, are kept as `cemi.Unknown`; Data Secure inside them is not
  decoded.
- Remote diagnosis and configuration (KNXnet/IP 0x0740-0x0744) is kept as
  `knxnetip.Unknown`.

## Restrictions

- **Tool access as a tool** is verified against go-knx's own device only: no
  third-party device with tool access was available.
- **Secure device management** uses user 1 (the management user) only.
- **Virtual devices** are application layer only.
- **Server properties**: the friendly name is writable; the other properties
  of the device management connection are read only.
- **Routing flow control** is honoured, not generated: go-knx never sends
  ROUTING_BUSY (the server drops routing indications its queue cannot hold
  and counts them), ROUTING_BUSY is applied whatever device its control
  field names, and ROUTING_LOST_MESSAGE is only reported. Checked against
  cB-Sigma knx-sim's router (knx-interop sim suite): go-knx's routing
  client waits the wait time after a ROUTING_BUSY and keeps going after a
  ROUTING_LOST_MESSAGE; the server's routing has no such third-party test.
- **Standard frames** carry an NPDU of at most 15 octets, enforced on encode
  and decode (Wireshark's synthetic cEMI captures hold standard frames up to
  248 octets, which go-knx refuses).
- **Link-layer repetitions**: `mgmt.Responder` has no TP1 data link layer.
  It acknowledges each repetition of a T_Data_Connected again (repeat flag,
  same sequence number), where the recorded TP1 devices answered once.
- **The server's M_Reset.req** does nothing: the virtual server has nothing
  to restart (a recorded ABB router restarts and ends its connections).
- **Many tunnelling addresses**: a description block has a one-octet
  length, so TUNNELLING_INFO lists the first 62 tunnelling slots and
  KNX_ADDRESSES the first 126 addresses. Each requested DIB type of an
  extended search is answered once.
- **Secure routing** remembers at most 4096 frames within the latency
  tolerance to refuse repeats; beyond that new frames are dropped until
  older ones expire. `routing.Listen` with `WithSecure` takes the whole
  synchronisation window (about 3.3 s at the default latency): give it a
  context that lasts longer, or it returns the context's error. A router
  that hears no time keeper in that window starts its own timer at the
  time since the process started ([SECURITY.md](SECURITY.md)).
- **A late devmgmt confirmation**: cEMI device management carries no
  correlation. `PropRead` and `PropWrite` discard the confirmations queued
  before they send their request, so a confirmation that arrived after
  its request timed out is not taken by the next request; one that
  arrives after the next request of the same property was sent is still
  taken for its answer.
- **Callbacks and Close**: `Close` of a client or server waits for the
  goroutine that runs a callback, so a callback calls it from another
  goroutine. A concurrent second `server.Server.Close` returns at once,
  before the first has finished.
- **Dialers**: `tunnel.WithDialer` supplies the TCP connection of a
  tunnel (and with it of `devmgmt.Dial` and `client.DialTunnel`). A UDP
  tunnel opens its own unconnected socket; an application cannot supply
  it. `WithDialer` does not combine with `WithLocalAddr`.
- **Key types print redacted**: the key types show `(redacted)` with the
  verbs of `fmt`, `%d` included, in `encoding/json` and in `log/slog`;
  `secure.Credentials` and the keyring entries, and a `keyring.Keyring`
  through them, show their keys and passwords redacted with the same
  verbs, in `encoding/json` and in `log/slog`; a `*datasecure.Table`, a
  `*secure.Session` and a `*secure.RoutingTimer` print a summary, `%#v`
  and `%d` too. JSON written this way does not read back into a key or a
  password. Not covered: `%p` of a key and `%w` outside `fmt.Errorf` (fmt
  calls no method of the value for them; `go vet` reports both);
  `encoding/xml` and `encoding/gob` write the octets of a key and the
  passwords.
- **A request whose caller left** before its TUNNELLING_ACK is not
  repeated: when the acknowledgement does not come within the request
  timeout, the next `Send` reports the connection as lost.
- **Keyrings** are read up to 4 MiB, 64 levels deep and 262144 elements.
- **Data Secure replay state** lives in the table: an application that
  does not persist `Table.Senders`, `Table.ToolSequences` and
  `Table.Sequence` accepts recorded telegrams again after a restart.
- **Description blocks**: an optional block of a known type that does not
  have its type's layout is kept as `knxnetip.UnknownDIB` when the
  DEVICE_INFO block decodes (as an ABB IP-Router IPR/S sends them).

Decisions where public sources leave a choice (rounding ties, timer start,
NAT endpoints) are listed under "Deviations and decisions" in
[docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md).
