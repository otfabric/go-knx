# Contributing to go-knx

Thank you for your interest in contributing.

## Getting started

```sh
git clone git@github.com:<your-username>/go-knx.git
cd go-knx
git checkout -b feature/my-change
```

## Prerequisites

- Go 1.23+ (see [go.mod](go.mod)); the code must build and pass on Go 1.23
- [staticcheck](https://staticcheck.dev/), [golangci-lint](https://golangci-lint.run/), [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- Docker, for the interop suite only
- Multicast on loopback for the discovery and routing tests (Linux works;
  on macOS the tests use lo0)

## Build and test

```sh
make check          # format, lint, vet, vuln, race tests, coverage gate, examples, cross builds
make test-multicast # Linux: the multicast tests must run, not skip
make fuzz           # every fuzz target, FUZZTIME=30s each
make interop-images # build the knx-interop adapter images (Docker)
make interop        # go-knx against Calimero, knxd, xknx, KNXUltimate
```

## Rules

- No cgo and no third-party runtime dependencies.
- SPDX header `// SPDX-License-Identifier: MIT` on every Go file.
- Every behaviour change comes with a test; decoders of untrusted input
  get a fuzz target.
- A compatibility claim needs an automated test against an independent
  implementation (knx-interop). Do not write skipped or simulated results
  as passes.
- Do not copy KNX specification text, tables or test vectors, and no code
  from other KNX stacks ([docs/standards/LICENSING.md](docs/standards/LICENSING.md)).
- Datapoint subtypes are added only with published semantics.
- Keep ARCHITECTURE.md, docs/IMPLEMENTATION-STATUS.md and the docs in step
  with the code.
- Add a `## vX.Y.Z` section to RELEASE.md for user-visible changes.
