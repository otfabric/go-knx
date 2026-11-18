#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The KNX master data (knx_master.xml) that dpt/masterdata_gen.go is
# generated from. The XML is downloaded into a cache that git ignores and
# never committed; dpt/masterdata.lock pins its URL, schema, version and
# SHA-256.
#
#   scripts/masterdata.sh fetch    download the pinned file, verify its SHA-256
#   scripts/masterdata.sh generate fetch, then regenerate dpt/masterdata_gen.go
#   scripts/masterdata.sh update   pin the newest published file, regenerate
#   scripts/masterdata.sh check    compare the pin with what is published now:
#                                  exit 0 in sync, 1 upstream differs, 2 error;
#                                  writes a report to stdout and, with
#                                  --diff-file FILE, the diff of the generated
#                                  Go to FILE
#
# update.knx.org keeps one file per ETS project schema (project-NN) and
# republishes it in place, so a pinned file can disappear: `generate` then
# fails with "upstream has changed" and `update` moves the pin.

set -euo pipefail
# comm, join and sort must agree on the order.
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="${ROOT}/dpt/masterdata.lock"
GEN="${ROOT}/dpt/masterdata_gen.go"
CACHE="${ROOT}/.cache/masterdata"
BASE_URL="https://update.knx.org/data/XML"
# A generic client name: no details of whoever runs the check.
UA="go-knx-masterdata"
# Schema numbers probed above the pinned one when looking for a newer
# folder (KNX numbers them 10-14, then 20-23).
PROBE=12

die() { echo "masterdata: $*" >&2; exit 2; }

lock_get() { awk -v k="$1" '$1 == k { print $2 }' "${LOCK}"; }

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
	else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

download() { # url file
	curl -fsSL --retry 3 --retry-delay 5 --max-time 120 -A "${UA}" -o "$2" "$1"
}

exists() { # url
	curl -fsIL --max-time 30 -A "${UA}" -o /dev/null "$1"
}

url_of() { echo "${BASE_URL}/project-$1/knx_master.xml"; }

# newest_schema prints the highest schema number published, starting from
# the pinned one.
newest_schema() {
	local pinned="$1" newest="$1" n
	for ((n = pinned + 1; n <= pinned + PROBE; n++)); do
		if exists "$(url_of "${n}")"; then newest="${n}"; fi
	done
	echo "${newest}"
}

# xml_version prints the Version of the MasterData element.
xml_version() {
	head -c 4096 "$1" | tr '\n' ' ' | sed -nE 's/.*<MasterData [^>]*Version="([0-9]+)".*/\1/p'
}

write_lock() { # file url schema version sha
	cat >"$1" <<EOF
# The KNX master data that dpt/masterdata_gen.go was generated from.
# Written by \`make masterdata-update\`; \`make generate\` downloads this file
# and refuses any other. The XML is not kept in the repository.
url $2
schema $3
version $4
sha256 $5
EOF
}

gendpt() { # xml lock out
	(cd "${ROOT}" && GOWORK=off go run ./internal/cmd/gendpt -in "$1" -lock "$2" -out "$3")
}

cmd_fetch() {
	[ -f "${LOCK}" ] || die "no ${LOCK}"
	local url want got
	url="$(lock_get url)"
	want="$(lock_get sha256)"
	mkdir -p "${CACHE}"
	if [ -f "${CACHE}/knx_master.xml" ] && [ "$(sha256 "${CACHE}/knx_master.xml")" = "${want}" ]; then
		return 0
	fi
	download "${url}" "${CACHE}/knx_master.xml.part" || die "cannot download ${url}"
	got="$(sha256 "${CACHE}/knx_master.xml.part")"
	if [ "${got}" != "${want}" ]; then
		rm -f "${CACHE}/knx_master.xml.part"
		die "${url}: sha256 ${got}, the lock has ${want}: upstream has changed (make masterdata-update)"
	fi
	mv "${CACHE}/knx_master.xml.part" "${CACHE}/knx_master.xml"
}

cmd_generate() {
	cmd_fetch
	gendpt "${CACHE}/knx_master.xml" "${LOCK}" "${GEN}"
	echo "dpt/masterdata_gen.go: master data schema $(lock_get schema), version $(lock_get version)"
}

# latest downloads the newest published file into $1 and writes a lock for
# it to $2.
latest() {
	local schema url
	schema="$(newest_schema "$(lock_get schema)")"
	url="$(url_of "${schema}")"
	download "${url}" "$1" || die "cannot download ${url}"
	write_lock "$2" "${url}" "${schema}" "$(xml_version "$1")" "$(sha256 "$1")"
}

cmd_update() {
	mkdir -p "${CACHE}"
	local xml="${CACHE}/latest.xml" lock="${CACHE}/latest.lock"
	latest "${xml}" "${lock}"
	gendpt "${xml}" "${lock}" "${GEN}"
	mv "${lock}" "${LOCK}"
	mv "${xml}" "${CACHE}/knx_master.xml"
	echo "dpt/masterdata.lock: schema $(lock_get schema), version $(lock_get version)"
}

cmd_check() {
	local diff_file=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--diff-file) diff_file="$2"; shift 2 ;;
		*) die "check: unknown argument $1" ;;
		esac
	done
	tmp="$(mktemp -d)"
	trap 'rm -rf "${tmp:-}"' EXIT
	latest "${tmp}/knx_master.xml" "${tmp}/latest.lock"
	local pinned_url pinned_schema pinned_version pinned_sha url schema version sha
	pinned_url="$(lock_get url)"; pinned_schema="$(lock_get schema)"
	pinned_version="$(lock_get version)"; pinned_sha="$(lock_get sha256)"
	schema="$(awk '$1 == "schema" { print $2 }' "${tmp}/latest.lock")"
	version="$(awk '$1 == "version" { print $2 }' "${tmp}/latest.lock")"
	sha="$(awk '$1 == "sha256" { print $2 }' "${tmp}/latest.lock")"
	url="$(awk '$1 == "url" { print $2 }' "${tmp}/latest.lock")"
	echo "Pinned:    schema ${pinned_schema}, version ${pinned_version}, sha256 ${pinned_sha}"
	echo "           ${pinned_url}"
	echo "Published: schema ${schema}, version ${version}, sha256 ${sha}"
	echo "           ${url}"
	if [ "${sha}" = "${pinned_sha}" ]; then
		echo "In sync."
		return 0
	fi
	if ! gendpt "${tmp}/knx_master.xml" "${tmp}/latest.lock" "${tmp}/masterdata_gen.go" 2>"${tmp}/gendpt.err"; then
		echo
		echo "The generator fails on the published file:"
		cat "${tmp}/gendpt.err"
		[ -z "${diff_file}" ] || : >"${diff_file}"
		return 1
	fi
	# Subtypes added, removed and changed, from the generated tables: one
	# line per subtype, "main.sub<TAB>name<TAB>its generated block".
	blocks() {
		awk '
			/^[[:space:]]*\{ID: ID\{/ {
				if (id != "") print id "\t" name "\t" body
				match($0, /ID\{[0-9]+, [0-9]+\}/); id = substr($0, RSTART + 3, RLENGTH - 4); sub(/, /, ".", id)
				name = $0; sub(/.*Name: "/, "", name); sub(/".*/, "", name)
				body = $0; next
			}
			/^}$/ { if (id != "") print id "\t" name "\t" body; id = ""; next }
			id != "" { body = body $0 }
		' "$1" | sort -t "$(printf '\t')" -k1,1
	}
	blocks "${GEN}" >"${tmp}/old.blocks"
	blocks "${tmp}/masterdata_gen.go" >"${tmp}/new.blocks"
	cut -f1 "${tmp}/old.blocks" >"${tmp}/old.ids"
	cut -f1 "${tmp}/new.blocks" >"${tmp}/new.ids"
	local added removed changed
	added="$(comm -13 "${tmp}/old.ids" "${tmp}/new.ids" | join -t "$(printf '\t')" - "${tmp}/new.blocks" | cut -f1,2 | tr '\t' ' ')"
	removed="$(comm -23 "${tmp}/old.ids" "${tmp}/new.ids" | join -t "$(printf '\t')" - "${tmp}/old.blocks" | cut -f1,2 | tr '\t' ' ')"
	changed="$(comm -13 "${tmp}/old.blocks" "${tmp}/new.blocks" | cut -f1 | comm -12 - "${tmp}/old.ids" \
		| join -t "$(printf '\t')" - "${tmp}/new.blocks" | cut -f1,2 | tr '\t' ' ')"
	report() { # title list
		echo "$1: $(printf '%s' "$2" | grep -c . || true)"
		[ -z "$2" ] || printf '%s\n' "$2" | sed 's/^/  /'
	}
	echo
	report "Subtypes added" "${added}"
	report "Subtypes removed" "${removed}"
	report "Subtypes changed (name, text or format)" "${changed}"
	if [ -n "${diff_file}" ]; then
		diff -u --label dpt/masterdata_gen.go --label "published (schema ${schema}, version ${version})" \
			"${GEN}" "${tmp}/masterdata_gen.go" >"${diff_file}" || true
	fi
	return 1
}

case "${1:-}" in
fetch) cmd_fetch ;;
generate) cmd_generate ;;
update) cmd_update ;;
check) shift; cmd_check "$@" ;;
*) echo "usage: $0 fetch|generate|update|check [--diff-file FILE]" >&2; exit 2 ;;
esac
