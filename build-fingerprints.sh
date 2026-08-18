#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${FOXHOLE_DNS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
FOXCORE_ROOT="${FOXCORE_ROOT:-}"
SOURCE_REPO="${FINGERPRINT_SOURCE_REPO:-https://github.com/foxhole-team/foxhole-core.git}"
SOURCE_REF="${FINGERPRINT_SOURCE_REF:-main}"
MIN_APP_VERSION="${MIN_APP_VERSION:-0.0.1}"
ARTIFACT_NAME="${FINGERPRINT_ARTIFACT_NAME:-fingerprints.json}"
MANIFEST_NAME="${FINGERPRINT_MANIFEST_NAME:-fingerprint-manifest.json}"
SOURCE_INFO_NAME="${FINGERPRINT_SOURCE_INFO_NAME:-fingerprint-source-info.json}"
REQUIRE_SIGNATURE="${FOXHOLE_DNS_REQUIRE_SIGNATURE:-true}"
SIGNING_KEY_PATH="${FOXHOLE_DNS_SIGNING_KEY:-}"
SIGNING_KEY_PEM="${FOXHOLE_DNS_SIGNING_KEY_PEM:-}"
# Refuse near-empty bundles: a fingerprint profile needs an anonymity set.
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

# CI passes a pinned checkout; cloning is a local-development fallback.
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

  # Exclude provenance from the canonical digest so metadata-only edits do not invalidate a table.
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

# Publish one complete set; partial tables create a unique fingerprint.
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
      license: "GPL-3.0-or-later",
      profile_count: $profile_count,
      upstream_reference: "profile-specific provenance in foxhole-core/fingerprints; uTLS where available"
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
      license: "GPL-3.0-or-later",
      note: "Tables only; ClientHello generator logic remains in FoxHole Core. Profiles are copied after fingerprint_sha256 is re-derived. FoxHole Core records profile-specific provenance and compares against uTLS where an upstream table exists."
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
