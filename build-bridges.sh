#!/usr/bin/env bash
set -euo pipefail

# Mirrors the Tor Project's builtin bridges.
# Consumer contract:
#   manifest name   : foxhole-tor-bridges
#   manifest format : tor-bridges-json
#   artifact file   : bridges.json   (exact string, checked by the client)
#   artifact body   : moat "builtin" transport-to-bridge arrays

ROOT_DIR="${FOXHOLE_DNS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
SOURCE_URL="${BRIDGES_SOURCE_URL:-https://bridges.torproject.org/moat/circumvention/builtin}"
MIN_APP_VERSION="${MIN_APP_VERSION:-1.1.3}"
ARTIFACT_NAME="${BRIDGES_ARTIFACT_NAME:-bridges.json}"
MANIFEST_NAME="${BRIDGES_MANIFEST_NAME:-bridges-manifest.json}"
SOURCE_INFO_NAME="${BRIDGES_SOURCE_INFO_NAME:-bridges-source-info.json}"
REQUIRE_SIGNATURE="${FOXHOLE_DNS_REQUIRE_SIGNATURE:-true}"
SIGNING_KEY_PATH="${FOXHOLE_DNS_SIGNING_KEY:-}"
SIGNING_KEY_PEM="${FOXHOLE_DNS_SIGNING_KEY_PEM:-}"

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
need jq
need openssl
need sha256sum

mkdir -p "$OUT_DIR" "$WORK_DIR"

RAW_PATH="$WORK_DIR/builtin-bridges.raw.json"
curl --fail --silent --show-error --location \
  --max-time 60 --max-filesize 262144 \
  "$SOURCE_URL" -o "$RAW_PATH"

# Reject upstream drift before publishing dial addresses.
jq -e '
  type == "object"
  and (keys | length > 0)
  and (to_entries | all(
    (.key | type == "string" and length > 0)
    and (.value | type == "array" and length > 0
      and all(type == "string" and length > 0))
  ))
' "$RAW_PATH" >/dev/null || {
  printf 'Upstream bridges payload failed validation: %s\n' "$SOURCE_URL" >&2
  exit 1
}

TRANSPORT_COUNT="$(jq 'keys | length' "$RAW_PATH")"
BRIDGE_COUNT="$(jq '[.[] | length] | add' "$RAW_PATH")"

ARTIFACT_PATH="$OUT_DIR/$ARTIFACT_NAME"
# Keep artifact bytes deterministic.
jq --sort-keys --indent 2 '.' "$RAW_PATH" > "$ARTIFACT_PATH"

ARTIFACT_SIZE="$(wc -c < "$ARTIFACT_PATH" | tr -d ' ')"
ARTIFACT_SHA256="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
printf '%s  %s\n' "$ARTIFACT_SHA256" "$ARTIFACT_NAME" > "$OUT_DIR/$ARTIFACT_NAME.sha256"

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
  --arg generated_at "$GENERATED_AT" \
  --arg file "$ARTIFACT_NAME" \
  --arg sha256 "$ARTIFACT_SHA256" \
  --arg min_app_version "$MIN_APP_VERSION" \
  --argjson size "$ARTIFACT_SIZE" \
  --argjson transports "$TRANSPORT_COUNT" \
  --argjson bridges "$BRIDGE_COUNT" \
  '{
    schema: 1,
    name: "foxhole-tor-bridges",
    format: "tor-bridges-json",
    generated_at: $generated_at,
    source: {
      name: "bridges.torproject.org builtin bridges",
      transport_count: $transports,
      bridge_count: $bridges
    },
    artifact: {
      file: $file,
      size: $size,
      sha256: $sha256
    },
    compatibility: {
      min_app_version: $min_app_version
    }
  }' > "$OUT_DIR/$MANIFEST_NAME"

jq -n \
  --arg generated_at "$GENERATED_AT" \
  --arg source_url "$SOURCE_URL" \
  --argjson transports "$TRANSPORT_COUNT" \
  --argjson bridges "$BRIDGE_COUNT" \
  '{
    schema: 1,
    generated_at: $generated_at,
    source: {
      name: "Tor Project builtin bridges (moat circumvention API)",
      url: $source_url,
      note: "Mirrored verbatim after shape validation; no bridge line is edited or added."
    },
    counts: {
      transports: $transports,
      bridges: $bridges
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

printf 'Built %s\n' "$ARTIFACT_PATH"
printf '  transports=%s bridges=%s size=%s signed=%s\n' \
  "$TRANSPORT_COUNT" "$BRIDGE_COUNT" "$ARTIFACT_SIZE" "$SIGNED"
