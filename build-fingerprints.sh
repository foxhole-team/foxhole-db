#!/usr/bin/env bash
set -euo pipefail

# Mirrors FoxHole Core's committed TLS fingerprint tables.
# Client-checked contract: manifest foxhole-tls-fingerprints / tls-fingerprint-tables-json,
# artifact fingerprints.json, one entry per profile in `fingerprints/` upstream.
#
# Only the *tables* travel. The ClientHello generator stays compiled into the
# application, so this feed can change which bytes a parrot chooses from a fixed
# set of fields, and can never introduce new behaviour. Every profile carries the
# upstream `fingerprint_sha256`, and this script re-derives it before publishing:
# a table that reaches the app is a table whose bytes were checked twice.

ROOT_DIR="${FOXHOLE_DNS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
FOXCORE_ROOT="${FOXCORE_ROOT:-}"
SOURCE_REPO="${FINGERPRINT_SOURCE_REPO:-https://github.com/foxhole-team/foxhole-core.git}"
SOURCE_REF="${FINGERPRINT_SOURCE_REF:-main}"
# CI sets this for every feed (.github/workflows/feeds.yml). The default must stay at or
# below the oldest client still in the field: a manifest declaring a version above the
# installed app is refused whole, and the app keeps its built-in data with no visible error.
MIN_APP_VERSION="${MIN_APP_VERSION:-0.0.1}"
ARTIFACT_NAME="${FINGERPRINT_ARTIFACT_NAME:-fingerprints.json}"
MANIFEST_NAME="${FINGERPRINT_MANIFEST_NAME:-fingerprint-manifest.json}"
SOURCE_INFO_NAME="${FINGERPRINT_SOURCE_INFO_NAME:-fingerprint-source-info.json}"
REQUIRE_SIGNATURE="${FOXHOLE_DNS_REQUIRE_SIGNATURE:-true}"
SIGNING_KEY_PATH="${FOXHOLE_DNS_SIGNING_KEY:-}"
SIGNING_KEY_PEM="${FOXHOLE_DNS_SIGNING_KEY_PEM:-}"
# A parrot the app can actually hide in needs a population to hide in. One profile
# is a fingerprint of its own, so refuse to publish a near-empty table set.
MIN_PROFILES="${FINGERPRINT_MIN_PROFILES:-4}"
MAX_BUNDLE_BYTES="${FINGERPRINT_MAX_BUNDLE_BYTES:-4194304}"

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

need git
need jq
need openssl
need sha256sum

mkdir -p "$OUT_DIR" "$WORK_DIR"

# The tables are a source input like any other. Prefer a checkout the caller
# already pinned (this is what .github/workflows/feeds.yml passes), and clone
# only as a local-developer convenience.
SOURCE_REVISION=""
if [[ -n "$FOXCORE_ROOT" ]]; then
  if [[ ! -d "$FOXCORE_ROOT/fingerprints" ]]; then
    printf 'FOXCORE_ROOT has no fingerprints/ directory: %s\n' "$FOXCORE_ROOT" >&2
    exit 1
  fi
  UPSTREAM_DIR="$FOXCORE_ROOT"
  SOURCE_LABEL="$FOXCORE_ROOT"
  SOURCE_REVISION="$(git -C "$UPSTREAM_DIR" rev-parse HEAD 2>/dev/null || true)"
else
  UPSTREAM_DIR="$WORK_DIR/foxhole-core"
  git clone --depth 1 --filter=blob:none --sparse --branch "$SOURCE_REF" "$SOURCE_REPO" "$UPSTREAM_DIR"
  git -C "$UPSTREAM_DIR" sparse-checkout set --no-cone /fingerprints
  SOURCE_REVISION="$(git -C "$UPSTREAM_DIR" rev-parse HEAD)"
  SOURCE_LABEL="$SOURCE_REPO#$SOURCE_REF"
fi

FINGERPRINT_DIR="$UPSTREAM_DIR/fingerprints"
PROFILE_LIST="$WORK_DIR/profiles.txt"
find "$FINGERPRINT_DIR" -maxdepth 1 -type f -name '*.json' -print |
  LC_ALL=C sort > "$PROFILE_LIST"

PROFILE_PATHS=()
while IFS= read -r profile; do
  [[ -n "$profile" ]] || continue
  PROFILE_PATHS+=("$profile")
done < "$PROFILE_LIST"
PROFILE_COUNT="${#PROFILE_PATHS[@]}"
if ((PROFILE_COUNT < MIN_PROFILES)); then
  printf 'Only %s fingerprint profile(s) upstream; at least %s are required.\n' \
    "$PROFILE_COUNT" "$MIN_PROFILES" >&2
  exit 1
fi

# Per-profile acceptance. The app fully re-validates on install; this rejects
# obvious upstream drift before it is signed.
check_profile() {
  local path="$1" base name declared derived
  base="$(basename "$path" .json)"

  jq -e . "$path" >/dev/null 2>&1 || {
    printf '%s is not valid JSON\n' "$path" >&2
    exit 1
  }
  jq -e '.schema == 1' "$path" >/dev/null || {
    printf '%s is not schema 1\n' "$path" >&2
    exit 1
  }
  name="$(jq -r '.name // empty' "$path")"
  [[ "$name" == "$base" ]] || {
    printf '%s declares name "%s"; the file name is the profile id\n' "$path" "$name" >&2
    exit 1
  }
  jq -e '.fingerprint | type == "object" and (keys | length > 0)' "$path" >/dev/null || {
    printf '%s carries no fingerprint object\n' "$path" >&2
    exit 1
  }
  jq -e '.describes | type == "string" and length > 0' "$path" >/dev/null || {
    printf '%s carries no "describes" line\n' "$path" >&2
    exit 1
  }

  # The digest convention, restated from the upstream files: SHA-256 over the
  # `fingerprint` object serialised with sorted keys, no whitespace and ASCII-only
  # content. Provenance and citations are excluded on purpose, so editing prose
  # upstream does not invalidate the vector.
  declared="$(jq -r '.fingerprint_sha256 // empty' "$path")"
  derived="$(jq -cSa '.fingerprint' "$path" | tr -d '\n' | sha256sum | awk '{print $1}')"
  [[ -n "$declared" ]] || {
    printf '%s carries no fingerprint_sha256\n' "$path" >&2
    exit 1
  }
  [[ "$declared" == "$derived" ]] || {
    printf '%s declares fingerprint_sha256 %s but its table hashes to %s\n' \
      "$path" "$declared" "$derived" >&2
    exit 1
  }
}

for profile in "${PROFILE_PATHS[@]}"; do
  check_profile "$profile"
done

# One artifact, one signature, one install: the app either has the whole table set
# or keeps the built-in one. A partially applied set is a fingerprint nobody shares.
BUNDLE_WORK="$WORK_DIR/$ARTIFACT_NAME"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -s \
  --arg generated_at "$GENERATED_AT" \
  '{
    schema: 1,
    generated_at: $generated_at,
    profiles: sort_by(.name)
  }' "${PROFILE_PATHS[@]}" > "$BUNDLE_WORK"

BUNDLE_SIZE="$(wc -c < "$BUNDLE_WORK" | tr -d ' ')"
if ((BUNDLE_SIZE > MAX_BUNDLE_BYTES)); then
  printf 'Bundle is %s bytes, over the %s byte ceiling\n' "$BUNDLE_SIZE" "$MAX_BUNDLE_BYTES" >&2
  exit 1
fi
jq -e --argjson want "$PROFILE_COUNT" '.profiles | length == $want' "$BUNDLE_WORK" >/dev/null || {
  printf 'Bundle does not carry all %s profiles\n' "$PROFILE_COUNT" >&2
  exit 1
}

mv "$BUNDLE_WORK" "$OUT_DIR/$ARTIFACT_NAME"

ARTIFACT_SIZE="$(wc -c < "$OUT_DIR/$ARTIFACT_NAME" | tr -d ' ')"
ARTIFACT_SHA256="$(sha256sum "$OUT_DIR/$ARTIFACT_NAME" | awk '{print $1}')"
printf '%s  %s\n' "$ARTIFACT_SHA256" "$ARTIFACT_NAME" > "$OUT_DIR/$ARTIFACT_NAME.sha256"

PROFILE_NAMES="$(jq -r '[.profiles[].name] | join(", ")' "$OUT_DIR/$ARTIFACT_NAME")"

jq -n \
  --arg generated_at "$GENERATED_AT" \
  --arg file "$ARTIFACT_NAME" \
  --arg sha256 "$ARTIFACT_SHA256" \
  --arg min_app_version "$MIN_APP_VERSION" \
  --argjson size "$ARTIFACT_SIZE" \
  --argjson profile_count "$PROFILE_COUNT" \
  '{
    schema: 1,
    name: "foxhole-tls-fingerprints",
    format: "tls-fingerprint-tables-json",
    generated_at: $generated_at,
    source: {
      repo: "https://github.com/foxhole-team/foxhole-core",
      dataset: "fingerprints",
      license: "GPL-3.0",
      profile_count: $profile_count,
      upstream_reference: "refraction-networking/utls"
    },
    artifact: { file: $file, size: $size, sha256: $sha256 },
    compatibility: {
      min_app_version: $min_app_version
    }
  }' > "$OUT_DIR/$MANIFEST_NAME"

jq -n \
  --arg generated_at "$GENERATED_AT" \
  --arg source_base "$SOURCE_LABEL" \
  --arg source_revision "$SOURCE_REVISION" \
  --arg profiles "$PROFILE_NAMES" \
  --argjson profile_count "$PROFILE_COUNT" \
  '{
    schema: 1,
    generated_at: $generated_at,
    source: {
      name: "foxhole-team/foxhole-core · fingerprints/",
      base_url: $source_base,
      revision: $source_revision,
      profile_count: $profile_count,
      profiles: ($profiles | split(", ")),
      license: "GPL-3.0",
      note: "Tables only. The ClientHello generator is compiled into the application; this feed can never add behaviour. Each profile is mirrored verbatim after its fingerprint_sha256 was re-derived here, and the tables themselves are checked against refraction-networking/utls by foxhole-core scripts/fingerprint-from-utls.py."
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

printf 'Built %s (%s profiles: %s)\n' "$OUT_DIR/$ARTIFACT_NAME" "$PROFILE_COUNT" "$PROFILE_NAMES"
printf '  size=%s bytes signed=%s\n' "$ARTIFACT_SIZE" "$SIGNED"
