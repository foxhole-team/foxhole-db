#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/public}"
export OUT_DIR

mkdir -p "$OUT_DIR"
"$ROOT_DIR/build-adguard-dns-filter.sh"
"$ROOT_DIR/build-threat-intel.sh"
"$ROOT_DIR/build-bridges.sh"
"$ROOT_DIR/build-geoip.sh"
if [[ "${FOXHOLE_DNS_REQUIRE_SIGNATURE:-true}" == "true" ]]; then
  "$ROOT_DIR/verify-feeds.sh" "$OUT_DIR"
else
  FOXHOLE_VERIFY_SIGNATURES=false "$ROOT_DIR/verify-feeds.sh" "$OUT_DIR"
fi
