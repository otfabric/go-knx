# AGENTS.md — go-knx

## What this is

Pure Go KNX over KNXnet/IP: frames, cEMI, datapoint types, discovery, tunnelling, routing, group communication, a KNXnet/IP server with virtual devices, KNX IP Secure and KNX Data Secure. No cgo, no dependencies. Profile: **protocol-library**. Not KNX certified and no conformance claim (docs/standards/CONFORMANCE.md).

## Organisation standards

This repository follows **otfabric/engineering policy 1.2**, profile **protocol-library** (`.otfabric/policy.yaml`, mode `enforce`). Where this file and the organisation standards disagree, this file wins here — say so in your report.

## Where the truth lives

| Question | Source |
|---|---|
| Sources used, and how they may be used | docs/standards/SPECIFICATIONS.md, docs/standards/LICENSING.md |
| What is supported and verified | docs/IMPLEMENTATION-STATUS.md, INTEROPERABILITY.md, LIMITATIONS.md |
| How to test | TESTING.md |
| Errors | ERRORS.md |
| Release history | RELEASE.md (`## vX.Y.Z` … `---`) |

## Hard rules

1. Never lower `COVER_MIN` (90), add lint suppressions, or skip or delete tests to make CI pass.
2. Do not copy KNX specification text, tables or test vectors, and no code from other KNX stacks.
3. A compatibility claim needs an automated test against an independent implementation (knx-interop). Do not write skipped or simulated results as passes.
4. No cgo and no third-party runtime dependencies.
5. Datapoint subtypes are added only with published semantics.

## Commands

| When you change… | Run |
|---|---|
| anything | `make check` |
| discovery or routing | `make test-multicast` (Linux; `KNX_REQUIRE_MULTICAST=1` turns skips into failures) |
| a decoder | `make fuzz` (a new decoder needs a fuzz target) |
| interop-relevant behaviour | `make interop-images interop`, `make interop-matrix` (Docker) |

## Definition of Done

`make check` green; tests for new behaviour including error paths; ARCHITECTURE.md and docs/IMPLEMENTATION-STATUS.md in step with the code; RELEASE.md section for user-visible changes; failing or skipped steps reported.

## Git and releases

Branches and PRs. Do not push to `main`, tag or run the Release workflow unless the maintainer asks in the session.
