# SPDX-License-Identifier: MIT
# go-knx's knx-interop adapter: the node binary (built from this
# repository's sources by `make interop-matrix`, context bin/node) and the
# knx-interop KNX Secure test profile, copied from a knx-interop image.
ARG BASE_REGISTRY=docker.io/library
ARG PROFILE_IMAGE=ghcr.io/otfabric/knx-interop-xknx:dev
FROM ${PROFILE_IMAGE} AS profile

FROM ${BASE_REGISTRY}/debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
COPY --from=profile /adapter/common/secure/ /adapter/common/secure/
COPY node /adapter/run
RUN /adapter/run capabilities
LABEL org.opencontainers.image.source="https://github.com/otfabric/go-knx" \
      org.opencontainers.image.description="go-knx's adapter for the knx-interop matrix (container contract 1.3)" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["/adapter/run"]
