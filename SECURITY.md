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

Implemented from public sources (xknx's MIT implementation and the KNX
keyring article; the KNX application notes 158/159 were not available) and
verified for interoperability with xknx 4.0.0 and Calimero 3.0-M1 — **not**
verified for conformance, and not certified
([SPECIFICATIONS](docs/standards/SPECIFICATIONS.md#knx-secure-sources)).

| Feature | Covered | Not covered |
|---|---|---|
| Secure tunnelling (`tunnel.WithSecure`, `server.WithSecure`) | X25519 session, user authentication, device authentication (client verifies when given the code), SECURE_WRAPPER with replay protection, keep alive, close; server binds users to tunnelling addresses, device management for user 1 only | secure sessions over UDP; secure device management by remote tools beyond property access |
| Secure routing (`routing.WithSecure`) | backbone key, timer synchronisation as keeper or follower, latency tolerance | the server's own routing (`server.WithRouting`) stays plain |
| Data Secure (`datasecure`, `client.WithDataSecure`) | S-A_Data with authentication and confidentiality (or authentication only) for group communication, per sender sequence numbers | S-A_Sync (a peer that asks go-knx for its sequence number gets no answer), point to point security, tool keys |
| Keyrings (`keyring`) | signature check, decryption, lookups, writing test keyrings | — |

Behaviour that matters for security:

- A client configured for security never falls back to a plain
  connection: a failed handshake is an error (`knx.ErrSecurity`).
- A secure server refuses plain connection requests (E_CONNECTION_TYPE);
  search and description stay plain, as the standard requires.
- Frames that fail authentication, replay an old sequence number or carry
  an outdated routing timer are dropped and counted
  (`Metrics.OnDecodeError` / `OnDropped`), never delivered.
- A client with Data Secure drops plain telegrams to secured groups.
- The secure session's frames are sealed with AES-128-CCM; the key
  agreement is X25519 (`crypto/ecdh`); comparisons of MACs are constant
  time.
- A Data Secure table starts its sending sequence number at the
  milliseconds since 2018-01-05 when none is given; persist
  `Table.Sequence()` if the clock may go backwards.

## Recommendations

- Put KNX IP traffic on its own VLAN or physical network; never expose UDP
  3671 to the internet. Reach installations remotely through a VPN.
- Allow only the hosts that need it to reach KNXnet/IP interfaces (host
  firewall, switch ACLs); block multicast 224.0.23.12 from other segments.
- Prefer discovery and passive monitoring for diagnostics; send telegrams
  only to installations you are responsible for.
- Where devices support it, use KNX IP Secure and Data Secure.
- Run go-knx servers with the fewest tunnelling addresses you need.

## Credential handling

Keys and passwords are never logged and never appear in error messages
(errors name users and addresses only). The library takes derived keys
(`secure.Key`) or passwords and derives them once (PBKDF2-HMAC-SHA256,
65536 iterations); it keeps them in memory for the life of the connection.
knxctl reads secrets from environment variables or the keyring by default
(`KNXCTL_KEYRING_PASSWORD`, `KNXCTL_USER_PASSWORD`, ...); command-line
flags exist for tests and should be avoided on shared hosts.

## Known limitations

- Routing write deadlines are 1 s: a blocked multicast send drops the
  telegram rather than stalling the server.
- The server accepts tunnelling requests from the client's IP address
  (control or data endpoint); it does not pin the source port.
