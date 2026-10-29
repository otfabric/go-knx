# Conformance and certification

**go-knx is not KNX certified and claims no conformance to the KNX
standard.** Certification requires KNX Association membership and testing
at an accredited test lab, with tools (EITT) licensed to members and labs
only ([LICENSING.md](LICENSING.md)).

What go-knx offers instead is evidence, kept reproducible:

| Evidence | Where | What it shows |
|---|---|---|
| Unit tests, golden frames, round trips | each package's `*_test.go`, `testdata/` | Frames encode and decode to the structures of the standard as we read it |
| Fuzz tests | `make fuzz` | Malformed input never panics or allocates without bound |
| End-to-end tests over loopback sockets | `e2e/` | Client, server, discovery and devices work together |
| Interoperability with independent implementations | [knx-interop](https://github.com/otfabric/knx-interop) reports, `interop/` | Calimero, knxd, xknx and KNXUltimate exchange frames with go-knx, both directions, with recorded versions |
| Negative tests by a raw probe | knx-interop `probe` adapter | Servers (go-knx and the others) survive malformed and hostile datagrams and answer with the status codes of the standard |

Interoperability with several independent stacks is not conformance: the
stacks may share a misreading, or all deviate from the standard in the same
way. Where they disagree, the behaviour chosen and why is written in
IMPLEMENTATION-STATUS.md ("Deviations and decisions").

## Wording rules for this project

- Say "interoperates with Calimero 3.0-M1 in scenario X", never "KNX
  compliant" or "certified".
- State the implementation versions behind every interoperability claim.
- Unsupported features are listed as unsupported, not as "partial".
