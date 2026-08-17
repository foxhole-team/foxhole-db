#!/usr/bin/env bash
set -euo pipefail

# Mirrors the DB-IP Lite country ranges (CC BY 4.0).
# Consumer contract:
#   manifest name   : foxhole-geoip
#   manifest format : dbip-country-csv
#   version         : upstream package.json version (the app's up-to-date probe)
#   artifact files  : dbip-country-ipv4.csv, dbip-country-ipv6.csv
#   artifact bodies : unmodified "start,end,CC" upstream CSVs

ROOT_DIR="${FOXHOLE_DNS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
SOURCE_REPO="${GEOIP_SOURCE_REPO:-https://github.com/sapics/ip-location-db.git}"
SOURCE_REF="${GEOIP_SOURCE_REF:-main}"
SOURCE_BASE="${GEOIP_SOURCE_BASE:-}"
SOURCE_CHECKOUT="${GEOIP_SOURCE_CHECKOUT:-}"
MIN_APP_VERSION="${MIN_APP_VERSION:-1.1.3}"
IPV4_NAME="${GEOIP_IPV4_NAME:-dbip-country-ipv4.csv}"
IPV6_NAME="${GEOIP_IPV6_NAME:-dbip-country-ipv6.csv}"
MANIFEST_NAME="${GEOIP_MANIFEST_NAME:-geoip-manifest.json}"
SOURCE_INFO_NAME="${GEOIP_SOURCE_INFO_NAME:-geoip-source-info.json}"
REQUIRE_SIGNATURE="${FOXHOLE_DNS_REQUIRE_SIGNATURE:-true}"
SIGNING_KEY_PATH="${FOXHOLE_DNS_SIGNING_KEY:-}"
SIGNING_KEY_PEM="${FOXHOLE_DNS_SIGNING_KEY_PEM:-}"
# Reject truncated/error responses and unexpectedly large upstream artifacts.
MIN_CSV_BYTES="${GEOIP_MIN_CSV_BYTES:-1048576}"
MAX_CSV_BYTES="${GEOIP_MAX_CSV_BYTES:-67108864}"

cleanup() {
  if [[ "${KEEP_WORK_DIR:-false}" != "true" && -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  }
}

need curl
need git
need jq
need openssl
need sha256sum

mkdir -p "$OUT_DIR" "$WORK_DIR"

fetch() {
  local url="$1" target="$2"
  curl --fail --silent --show-error --location \
    --connect-timeout 20 --max-time 900 --max-filesize "$MAX_CSV_BYTES" \
    --retry 4 --retry-all-errors --retry-delay 5 \
    "$url" -o "$target"
}

PACKAGE_PATH="$WORK_DIR/package.json"
IPV4_WORK="$WORK_DIR/$IPV4_NAME"
IPV6_WORK="$WORK_DIR/$IPV6_NAME"
SOURCE_REVISION=""
if [[ -n "$SOURCE_BASE" ]]; then
  fetch "$SOURCE_BASE/package.json" "$PACKAGE_PATH"
  fetch "$SOURCE_BASE/dbip-country-ipv4.csv" "$IPV4_WORK"
  fetch "$SOURCE_BASE/dbip-country-ipv6.csv" "$IPV6_WORK"
  SOURCE_LABEL="$SOURCE_BASE"
else
  if [[ -n "$SOURCE_CHECKOUT" ]]; then
    UPSTREAM_DIR="$SOURCE_CHECKOUT"
    git -C "$UPSTREAM_DIR" rev-parse --is-inside-work-tree >/dev/null
  else
    UPSTREAM_DIR="$WORK_DIR/ip-location-db"
    git clone --depth 1 --filter=blob:none --sparse --branch "$SOURCE_REF" "$SOURCE_REPO" "$UPSTREAM_DIR"
    git -C "$UPSTREAM_DIR" sparse-checkout set --no-cone \
      /dbip-country/package.json \
      /dbip-country/dbip-country-ipv4.csv \
      /dbip-country/dbip-country-ipv6.csv
  fi
  SOURCE_REVISION="$(git -C "$UPSTREAM_DIR" rev-parse HEAD)"
  cp "$UPSTREAM_DIR/dbip-country/package.json" "$PACKAGE_PATH"
  cp "$UPSTREAM_DIR/dbip-country/dbip-country-ipv4.csv" "$IPV4_WORK"
  cp "$UPSTREAM_DIR/dbip-country/dbip-country-ipv6.csv" "$IPV6_WORK"
  SOURCE_LABEL="$SOURCE_REPO#$SOURCE_REF"
fi
VERSION="$(jq -er '.version' "$PACKAGE_PATH" | tr -d ' ')"
[[ -n "$VERSION" ]] || {
  printf 'Upstream package.json carries no version\n' >&2
  exit 1
}

check_csv() {
  local path="$1" label="$2"
  local size
  size="$(wc -c < "$path" | tr -d ' ')"
  if (( size < MIN_CSV_BYTES )); then
    printf '%s too small: %s bytes\n' "$label" "$size" >&2
    exit 1
  fi
  # The app fully validates on install; reject obvious upstream drift here.
  head -n 20 "$path" | grep -Eq '^[0-9a-fA-F.:]+,[0-9a-fA-F.:]+,[A-Z]{2}$' || {
    printf '%s does not look like "start,end,CC" range lines\n' "$label" >&2
    exit 1
  }
}

check_csv "$IPV4_WORK" "$IPV4_NAME"
check_csv "$IPV6_WORK" "$IPV6_NAME"

mv "$IPV4_WORK" "$OUT_DIR/$IPV4_NAME"
mv "$IPV6_WORK" "$OUT_DIR/$IPV6_NAME"

IPV4_SIZE="$(wc -c < "$OUT_DIR/$IPV4_NAME" | tr -d ' ')"
IPV6_SIZE="$(wc -c < "$OUT_DIR/$IPV6_NAME" | tr -d ' ')"
IPV4_SHA256="$(sha256sum "$OUT_DIR/$IPV4_NAME" | awk '{print $1}')"
IPV6_SHA256="$(sha256sum "$OUT_DIR/$IPV6_NAME" | awk '{print $1}')"
printf '%s  %s\n' "$IPV4_SHA256" "$IPV4_NAME" > "$OUT_DIR/$IPV4_NAME.sha256"
printf '%s  %s\n' "$IPV6_SHA256" "$IPV6_NAME" > "$OUT_DIR/$IPV6_NAME.sha256"

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg generated_at "$GENERATED_AT" \
  --arg version "$VERSION" \
  --arg ipv4_file "$IPV4_NAME" \
  --arg ipv4_sha256 "$IPV4_SHA256" \
  --arg ipv6_file "$IPV6_NAME" \
  --arg ipv6_sha256 "$IPV6_SHA256" \
  --arg min_app_version "$MIN_APP_VERSION" \
  --argjson ipv4_size "$IPV4_SIZE" \
  --argjson ipv6_size "$IPV6_SIZE" \
  '{
    schema: 1,
    name: "foxhole-geoip",
    format: "dbip-country-csv",
    generated_at: $generated_at,
    version: $version,
    source: {
      repo: "https://github.com/sapics/ip-location-db",
      dataset: "dbip-country",
      license: "CC BY 4.0 (DB-IP Lite)",
      attribution: "IP Geolocation by DB-IP (https://db-ip.com)"
    },
    artifacts: [
      { file: $ipv4_file, size: $ipv4_size, sha256: $ipv4_sha256 },
      { file: $ipv6_file, size: $ipv6_size, sha256: $ipv6_sha256 }
    ],
    compatibility: {
      min_app_version: $min_app_version
    }
  }' > "$OUT_DIR/$MANIFEST_NAME"

jq -n \
  --arg generated_at "$GENERATED_AT" \
  --arg version "$VERSION" \
  --arg source_base "$SOURCE_LABEL" \
  --arg source_revision "$SOURCE_REVISION" \
  '{
    schema: 1,
    generated_at: $generated_at,
    source: {
      name: "sapics/ip-location-db · dbip-country (DB-IP Lite)",
      base_url: $source_base,
      revision: $source_revision,
      version: $version,
      license: "CC BY 4.0",
      note: "CSVs are mirrored verbatim after size and shape checks; the attribution must stay visible in the app."
    }
  }' > "$OUT_DIR/$SOURCE_INFO_NAME"

SIGNATURE_PATH="$OUT_DIR/$MANIFEST_NAME.sig"
TEMP_KEY_PATH=""
if [[ -n "$SIGNING_KEY_PEM" ]]; then
  TEMP_KEY_PATH="$WORK_DIR/manifest.private.pem"
  umask 077
  printf '%s\n' "$SIGNING_KEY_PEM" > "$TEMP_KEY_PATH"
  SIGNING_KEY_PATH="$TEMP_KEY_PATH"
fi

SIGNED="false"
if [[ -n "$SIGNING_KEY_PATH" ]]; then
  openssl dgst -sha256 -sign "$SIGNING_KEY_PATH" -out "$SIGNATURE_PATH" "$OUT_DIR/$MANIFEST_NAME"
  SIGNED="true"
elif [[ "$REQUIRE_SIGNATURE" == "true" ]]; then
  printf 'NOT SIGNED: no signing key was provided.\n' >&2
  printf 'Set FOXHOLE_DNS_SIGNING_KEY or FOXHOLE_DNS_SIGNING_KEY_PEM, or rerun with\n' >&2
  printf 'FOXHOLE_DNS_REQUIRE_SIGNATURE=false for a local unsigned smoke build.\n' >&2
  if [[ -f "$SIGNATURE_PATH" ]]; then
    printf 'The existing %s is now stale and does not match this manifest.\n' "$SIGNATURE_PATH" >&2
  fi
  exit 1
else
  printf 'NOT SIGNED: no signing key was provided (unsigned local build).\n' >&2
  printf 'Never publish %s without a signature over its exact bytes.\n' "$MANIFEST_NAME" >&2
  if [[ -f "$SIGNATURE_PATH" ]]; then
    printf 'The existing %s is stale and does not match this manifest.\n' "$SIGNATURE_PATH" >&2
  fi
fi

printf 'Built %s + %s (version %s)\n' "$OUT_DIR/$IPV4_NAME" "$OUT_DIR/$IPV6_NAME" "$VERSION"
printf '  ipv4=%s bytes ipv6=%s bytes signed=%s\n' "$IPV4_SIZE" "$IPV6_SIZE" "$SIGNED"
