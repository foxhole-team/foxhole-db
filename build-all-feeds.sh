#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/public}"
export OUT_DIR

mkdir -p "$OUT_DIR"
"$ROOT_DIR/build-adguard-dns-filter.sh"
if [[ -z "${FOXCORE_DNS_COMPILE_BIN:-}" && -n "${FOXCORE_ROOT:-}" ]]; then
  export FOXCORE_DNS_COMPILE_BIN="${CARGO_TARGET_DIR:-$FOXCORE_ROOT/target}/release/foxcore-dns-compile"
fi
"$ROOT_DIR/build-dns-categories.sh"
"$ROOT_DIR/build-threat-intel.sh"
"$ROOT_DIR/build-bridges.sh"
"$ROOT_DIR/build-geoip.sh"
"$ROOT_DIR/build-fingerprints.sh"
if [[ "${FOXHOLE_DNS_REQUIRE_SIGNATURE:-true}" == "true" ]]; then
  "$ROOT_DIR/verify-feeds.sh" "$OUT_DIR"
else
  FOXHOLE_VERIFY_SIGNATURES=false "$ROOT_DIR/verify-feeds.sh" "$OUT_DIR"
fi
