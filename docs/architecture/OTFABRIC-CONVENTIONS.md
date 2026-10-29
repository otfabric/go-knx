# OT Fabric conventions adopted by go-knx, knx-interop and knxctl

The three KNX repositories follow the conventions of the most mature OT
Fabric protocol ecosystems. This document lists each convention, the
sibling files it was taken from, and where the KNX repositories differ.
Sibling links point at the default branch of each repository.

## Reference repositories

| Role | Reference | Why |
|---|---|---|
| Library | [go-canbus](https://github.com/otfabric/go-canbus), [go-ethernetip](https://github.com/otfabric/go-ethernetip), [go-profinet](https://github.com/otfabric/go-profinet) | Most recent and complete: zero dependencies, typed errors, Logger/Metrics, interop suites pinned by digest, fuzzing, coverage gates |
| CLI | [canbusctl](https://github.com/otfabric/canbusctl), [ethernetipctl](https://github.com/otfabric/ethernetipctl), [profinetctl](https://github.com/otfabric/profinetctl) | cobra command tree, `internal/errs` + `internal/output`, versioned JSON, stable exit codes |
| Interop | [canbus-interop](https://github.com/otfabric/canbus-interop), [ethernetip-interop](https://github.com/otfabric/ethernetip-interop), [profinet-interop](https://github.com/otfabric/profinet-interop) | One adapter image per third-party stack, a container contract with JSON result documents, `versions.yaml`, pinned base images |
| CI | [otfabric/.github](https://github.com/otfabric/.github) `go-ci.yml`, `go-package-release.yml`, `go-binary-release.yml` (`@v2`) | Organisation-wide reusable workflows |

## Library (go-knx)

| Convention | Source in siblings | In go-knx |
|---|---|---|
| Module `github.com/otfabric/go-<proto>`, Go 1.23 floor, no runtime dependencies, no cgo | go-canbus `go.mod`; go-ethernetip `go.mod` | `go.mod`: go 1.23, no requirements |
| Root package holds the shared sentinel errors, `Logger` (Std/slog adapters, FieldLogger, ContextLogger), `Metrics` + `NopMetrics`, `State` | go-ethernetip `errors.go`, `logger.go`, `metrics.go`, `state.go` | `errors.go`, `logger.go` (adapted copy), `metrics.go`, `state.go`, plus the address types |
| Subpackages per layer; client and server separate; codecs separate from transports | go-ethernetip `encap/`, `cip/`, `client/`, `server/` | `knxnetip/`, `cemi/`, `apdu/`, `dpt/`, `tunnel/`, `routing/`, `discovery/`, `client/`, `server/`, `device/` |
| Functional options returning errors (`Option func(*options) error`), validated at construction | go-ethernetip `client/options.go` | every package with a constructor |
| Errors wrapped with `%w` around sentinels; typed errors with `Is` (status codes) | go-ethernetip `CIPError.Is` | `knxnetip.StatusError` matches `knx.ErrRejected` / `knx.ErrBusy` |
| `context.Context` on every blocking call; goroutines owned and ended by `Close` | go-ethernetip `client` | `tunnel.Conn`, `server.Server`, `routing.Conn`, `client.Client` |
| SPDX header `// SPDX-License-Identifier: MIT` on every Go file; MIT LICENSE "Copyright (c) 2026 OT Fabric" | all siblings | all files |
| `Makefile` targets `check test coverage coverage-check fuzz bench cross interop interop-images coverpkg-check`, `GOWORK=off`, gofmt of the go.mod Go version | go-canbus `Makefile` | `Makefile` (no code generator: no `generate` target) |
| `.golangci.yml` v2 with errcheck, govet, ineffassign, staticcheck, misspell, godot, nilerr, exhaustive | go-canbus `.golangci.yml` | copied |
| Coverage across library packages with `-coverpkg`, gated in `make coverage-check`, uploaded to Codecov with OIDC; `codecov.yml` targets | go-canbus `codecov.yml`, `.github/workflows/ci.yml` | gate 85 % (task requirement), 90 % for the codec packages tracked in TESTING.md |
| `interop/` behind the build tag `interop`, consuming the interop repo's images pinned by digest; `KNX_REQUIRE_*` env vars turn skips into failures in CI | go-canbus `interop/harness_test.go`, `CANBUS_REQUIRE_VCAN` | `interop/` (tag `interop`), `KNX_REQUIRE_INTEROP`, `KNX_REQUIRE_MULTICAST` |
| Documentation set: README, ARCHITECTURE, API, ERRORS, OBSERVABILITY, INTEROPERABILITY, SECURITY, CONTRIBUTING, TESTING, RELEASE (versioned `## vX.Y.Z` sections closed by `---`) | go-canbus, go-ethernetip | same set, plus `docs/standards/`, `docs/IMPLEMENTATION-STATUS.md` (task deliverables) |
| Durable mission state | go-canbus `PROGRESS.md`, go-profinet `docs/FEATURE-STATUS.md` | `docs/IMPLEMENTATION-STATUS.md` |

## CLI (knxctl)

| Convention | Source | In knxctl |
|---|---|---|
| cobra; `cmd/` command tree; `main.go` with `-X main.version/tag/commit/buildDate` | canbusctl `main.go`, `cmd/root.go` | same |
| `--format text\|json\|table` (env `<TOOL>_FORMAT`), read before parsing so usage errors follow it | canbusctl `cmd/root.go` `formatOf` | `KNXCTL_FORMAT` |
| Versioned JSON envelope `{schemaVersion, command, result}`; JSON Lines streams with `schemaVersion` and `type`; error document `{schemaVersion, error:{kind,code,message}}` | canbusctl `internal/output/output.go`, `docs/json-output.md` | copied package, `docs/json-output.md` |
| Typed errors with stable codes and exit codes 0–10 | canbusctl `internal/errs/errs.go`, `docs/exitcodes.md` | adapted: `rejected` replaces `safety` (exit 9) |
| Passive by default; transmitting commands are explicit | canbusctl root help | `group write/respond/answer/read` are the only commands that send telegrams |
| `version` and `completion` commands | canbusctl | same |
| Release with `go-binary-release.yml@v2` (bump none/patch/minor/major) | canbusctl `.github/workflows/release.yml` | same |

## Interop (knx-interop)

| Convention | Source | In knx-interop |
|---|---|---|
| `adapters/<stack>/Dockerfile` per independent implementation, built from pinned upstream versions on digest-pinned base images | canbus-interop `adapters/`, `versions.yaml` | `adapters/{calimero-server,calimero-tools,knxd,xknx,knxultimate,goknx,probe}` |
| A container contract: roles, operations, one JSON result document per call, `capabilities` | canbus-interop `docs/CONTAINER_CONTRACT.md` | `docs/CONTAINER_CONTRACT.md` |
| `versions.yaml` as the machine-readable manifest, checked against the Dockerfiles | canbus-interop `versions.yaml`, `scripts/check-versions.sh` | `versions.yaml`, `scripts/check-versions.py` |
| Known differences recorded, not hidden | canbus-interop `tests/known-differences.tsv` | `tests/known-differences.tsv` |
| Tag-driven release, `interop_version` equals the tag; images to GHCR | canbus-interop `.github/workflows/release.yml` | same |
| Third-party licences respected; GPL images carry notices | profinet-interop (GPL images not published), canbus-interop `THIRD_PARTY_NOTICES.md` | `THIRD_PARTY_NOTICES.md` |

## Where the KNX repositories differ, and why

- **The interop matrix runs inside one Docker network**, including go-knx
  itself (through knxctl in the `goknx` adapter): KNXnet/IP discovery and
  routing need IP multicast between all participants, which a host test
  binary does not share with containers on macOS or in most CI setups.
  go-knx's own `interop/` suite covers the unicast scenarios from the host.
- **Coverage gate 85 %** (go-canbus uses 90 %): the task sets 85 % overall
  and 90 % for the codec packages.
- **No code generator**: the DPT registry is a reviewed table in Go.
