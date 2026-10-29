# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `go-knx`, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@otfabric.io**, or open a private advisory on GitHub (the [Security](https://github.com/otfabric/go-knx/security) tab → **Advisories** → **Report a vulnerability**), with a description, steps to reproduce (ideally a minimal program or the datagrams), the affected version(s) and the impact you see.

We will acknowledge your report within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (main) | Yes |

## Threat model

KNX controls lighting, blinds, heating, ventilation, access and alarms.
A KNXnet/IP network is part of a building's control system.

| Asset | Threat | What go-knx does | What it cannot do |
|---|---|---|---|
| The building's devices | Unauthorised telegrams (switch off heating, open blinds, trigger scenes) | Sends only what the application asks; never scans, probes or retransmits on its own beyond the protocol's one repetition | Prevent telegrams from others: plain KNXnet/IP has no authentication |
| Confidentiality of states | Eavesdropping on group values (presence, alarms) | — | Plain KNXnet/IP is not encrypted |
| The host running go-knx | Malformed or hostile datagrams | Strict decoding (no panics, fuzzed), bounded frame size (1024 octets), bounded queues, bounded connections, deadlines on every wait, rate-limited routing | — |
| A go-knx server | Resource exhaustion by many clients | Connection limit (one per tunnelling address), per-connection bounded queue, heartbeat timeout (120 s), refusal with the standard status codes | Rate limiting per source address (not implemented) |
| The KNX IP network | Telegram storms or loops through routing | Routing indications are rate limited (50/s by default); telegrams with hop count 0 are not routed; the server never re-routes indications received from multicast; routing.Conn never forwards | Loops created by other routers |

## KNXnet/IP security limitations

- **KNXnet/IP (tunnelling, routing, discovery) has no security of its own.**
  Any host that can reach UDP port 3671 or the multicast group 224.0.23.12
  can read and send telegrams.
- A tunnelling connection is identified by a channel number and the
  client's address; a host on the same network can spoof datagrams of a
  connected client.
- NAT mode (route back endpoints) makes the server answer to the source
  address of each datagram, which is spoofable.

## KNX IP Secure and KNX Data Secure

**Not implemented.** go-knx decodes the frame structures (SECURE_WRAPPER,
SESSION_*, TIMER_NOTIFY) so that monitors can show them, but it does not
establish secure sessions, does not encrypt or authenticate, and does not
read ETS keyrings. A client never silently falls back from a secure to a
plain connection because it has no secure connection at all; the secured
service families a server announces are shown by discovery. Status and
blockers: [docs/IMPLEMENTATION-STATUS.md](docs/IMPLEMENTATION-STATUS.md).

## Recommendations

- Put KNX IP traffic on its own VLAN or physical network; never expose UDP
  3671 to the internet. Reach installations remotely through a VPN.
- Allow only the hosts that need it to reach KNXnet/IP interfaces (host
  firewall, switch ACLs); block multicast 224.0.23.12 from other segments.
- Prefer discovery and passive monitoring for diagnostics; send telegrams
  only to installations you are responsible for.
- Where devices support it, use KNX IP Secure and Data Secure with a tool
  that implements them, until go-knx does.
- Run go-knx servers with the fewest tunnelling addresses you need.

## Credential handling

go-knx handles no credentials today. When KNX Secure is implemented, keys
and passwords will never be logged, never appear in error messages, and
will be accepted from files or environment variables in the tools, not
from command-line arguments.

## Known limitations

- Routing write deadlines are 1 s: a blocked multicast send drops the
  telegram rather than stalling the server.
- The server accepts tunnelling requests from the client's IP address
  (control or data endpoint); it does not pin the source port.
