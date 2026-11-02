#!/usr/bin/env bash
set -euo pipefail

# Mirrors Association Echap's public stalkerware indicators.

ROOT_DIR="${FOXHOLE_DNS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR}"
WORK_PARENT="${WORK_DIR:-${TMPDIR:-/tmp}}"
mkdir -p "$WORK_PARENT"
WORK_DIR="$(mktemp -d "$WORK_PARENT/foxhole-db-work.XXXXXXXX")"
OWNED_WORK_DIR="$WORK_DIR"
SOURCE_REPO="${THREAT_INTEL_SOURCE_REPO:-${SOURCE_REPO:-https://github.com/AssoEchap/stalkerware-indicators.git}}"
SOURCE_REF="${THREAT_INTEL_SOURCE_REF:-${SOURCE_REF:-HEAD}}"
MIN_APP_VERSION="${MIN_APP_VERSION:-0.0.1}"
ARTIFACT_NAME="${ARTIFACT_NAME:-threat-intel.json}"
MANIFEST_NAME="${THREAT_INTEL_MANIFEST_NAME:-threat-intel-manifest.json}"
SOURCE_INFO_NAME="${THREAT_INTEL_SOURCE_INFO_NAME:-threat-intel-source-info.json}"
# Exclude watchware by default to avoid classifying parental-control apps as threats.
INCLUDE_WATCHWARE="${INCLUDE_WATCHWARE:-false}"
# Preserve upstream com.example indicators unless explicitly disabled.
INCLUDE_EXAMPLE_PREFIX="${INCLUDE_EXAMPLE_PREFIX:-true}"
REQUIRE_SIGNATURE="${FOXHOLE_DNS_REQUIRE_SIGNATURE:-true}"
SIGNING_KEY_PATH="${FOXHOLE_DNS_SIGNING_KEY:-}"
SIGNING_KEY_PEM="${FOXHOLE_DNS_SIGNING_KEY_PEM:-}"
TEMP_KEY_PATH=""
PYTHON_BIN="${PYTHON_BIN:-python3}"

cleanup() {
  if [[ -n "$TEMP_KEY_PATH" ]]; then
    rm -f "$TEMP_KEY_PATH"
  fi
  if [[ "${KEEP_WORK_DIR:-false}" != "true" && -d "$OWNED_WORK_DIR" ]]; then
    rm -rf "$OWNED_WORK_DIR"
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
need "$PYTHON_BIN"

mkdir -p "$OUT_DIR" "$WORK_DIR"

# Parse YAML structurally to avoid false threat matches.
if ! "$PYTHON_BIN" -c 'import yaml' >/dev/null 2>&1; then
  printf 'PyYAML not available for %s, bootstrapping a build-local venv\n' "$PYTHON_BIN" >&2
  "$PYTHON_BIN" -m venv "$WORK_DIR/venv"
  "$WORK_DIR/venv/bin/pip" install --quiet --disable-pip-version-check \
    --only-binary=:all: pyyaml==6.0.3
  PYTHON_BIN="$WORK_DIR/venv/bin/python"
fi

SOURCE_DIR="$WORK_DIR/stalkerware-indicators"
if [[ "$SOURCE_REF" == "HEAD" ]]; then
  git clone --depth 1 "$SOURCE_REPO" "$SOURCE_DIR"
else
  git init "$SOURCE_DIR"
  git -C "$SOURCE_DIR" remote add origin "$SOURCE_REPO"
  git -C "$SOURCE_DIR" fetch --depth 1 origin "$SOURCE_REF"
  git -C "$SOURCE_DIR" checkout --detach FETCH_HEAD
fi

SOURCE_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"

IOC_FILE="$SOURCE_DIR/ioc.yaml"
WATCHWARE_FILE="$SOURCE_DIR/watchware.yaml"
if [[ ! -s "$IOC_FILE" ]]; then
  printf 'Missing upstream indicator file: %s\n' "$IOC_FILE" >&2
  exit 1
fi

INPUT_PATHS="ioc.yaml"
IOC_SHA256="$(sha256sum "$IOC_FILE" | awk '{print $1}')"
INPUT_SHA256="$IOC_SHA256"
WATCHWARE_SHA256=""
CONVERT_ARGS=("$IOC_FILE")
if [[ "$INCLUDE_WATCHWARE" == "true" ]]; then
  if [[ ! -s "$WATCHWARE_FILE" ]]; then
    printf 'INCLUDE_WATCHWARE=true but %s is missing\n' "$WATCHWARE_FILE" >&2
    exit 1
  fi
  WATCHWARE_SHA256="$(sha256sum "$WATCHWARE_FILE" | awk '{print $1}')"
  INPUT_PATHS="ioc.yaml,watchware.yaml"
  INPUT_SHA256="$(printf '%s  ioc.yaml\n%s  watchware.yaml\n' "$IOC_SHA256" "$WATCHWARE_SHA256" |
    sha256sum | awk '{print $1}')"
  CONVERT_ARGS+=("$WATCHWARE_FILE")
fi

ARTIFACT_PATH="$OUT_DIR/$ARTIFACT_NAME"
STATS_PATH="$WORK_DIR/conversion-stats.json"

ARTIFACT_PATH="$ARTIFACT_PATH" STATS_PATH="$STATS_PATH" \
  INCLUDE_EXAMPLE_PREFIX="$INCLUDE_EXAMPLE_PREFIX" \
  "$PYTHON_BIN" "$ROOT_DIR/tools/threat_intel_converter.py" "${CONVERT_ARGS[@]}"

if [[ ! -s "$ARTIFACT_PATH" ]]; then
  printf 'Conversion produced no artifact: %s\n' "$ARTIFACT_PATH" >&2
  exit 1
fi

PACKAGE_COUNT="$(jq '.packages | length' "$ARTIFACT_PATH")"
CERT_COUNT="$(jq '.certs | length' "$ARTIFACT_PATH")"
ENTRY_COUNT=$((PACKAGE_COUNT + CERT_COUNT))
if [[ "$ENTRY_COUNT" -eq 0 ]]; then
  printf 'Refusing to publish an empty threat-intel feed\n' >&2
  exit 1
fi

ARTIFACT_SHA256="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
ARTIFACT_SIZE="$(wc -c < "$ARTIFACT_PATH" | tr -d ' ')"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Match the client's artifact size bounds.
if [[ "$ARTIFACT_SIZE" -lt 2 || "$ARTIFACT_SIZE" -gt 4194304 ]]; then
  printf 'Artifact size %s is outside the client-accepted 2..4194304 byte range\n' "$ARTIFACT_SIZE" >&2
  exit 1
fi

printf '%s  %s\n' "$ARTIFACT_SHA256" "$ARTIFACT_NAME" > "$OUT_DIR/$ARTIFACT_NAME.sha256"

# Keep the manifest shape fixed; extra provenance belongs in source-info.
jq -n \
  --arg generated_at "$GENERATED_AT" \
  --arg file "$ARTIFACT_NAME" \
  --arg sha256 "$ARTIFACT_SHA256" \
  --arg min_app_version "$MIN_APP_VERSION" \
  --argjson size "$ARTIFACT_SIZE" \
  --argjson entry_count "$ENTRY_COUNT" \
  '{
    schema: 1,
    name: "foxhole-sentinel-threat-intel",
    format: "sentinel-threat-intel-json",
    generated_at: $generated_at,
    source: {
      name: "AssoEchap/stalkerware-indicators",
      license: "CC-BY-4.0",
      entry_count: $entry_count
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
  --arg source_repo "${SOURCE_REPO%.git}" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg input_paths "$INPUT_PATHS" \
  --arg input_sha256 "$INPUT_SHA256" \
  --arg ioc_sha256 "$IOC_SHA256" \
  --arg watchware_sha256 "$WATCHWARE_SHA256" \
  --arg include_watchware "$INCLUDE_WATCHWARE" \
  --arg include_example_prefix "$INCLUDE_EXAMPLE_PREFIX" \
  --arg file "$ARTIFACT_NAME" \
  --arg sha256 "$ARTIFACT_SHA256" \
  --arg min_app_version "$MIN_APP_VERSION" \
  --argjson size "$ARTIFACT_SIZE" \
  --argjson packages "$PACKAGE_COUNT" \
  --argjson certs "$CERT_COUNT" \
  --slurpfile stats "$STATS_PATH" \
  '{
    schema: 1,
    generated_at: $generated_at,
    source: {
      name: "AssoEchap/stalkerware-indicators",
      repo: $source_repo,
      commit: $source_commit,
      license: "CC-BY-4.0",
      license_url: "https://creativecommons.org/licenses/by/4.0/",
      attribution: "Stalkerware Indicators List by Association Echap, CC-BY 4.0",
      input_paths: ($input_paths | split(",")),
      input_sha256: $input_sha256,
      input_file_sha256: (
        {"ioc.yaml": $ioc_sha256}
        + (if $watchware_sha256 == "" then {} else {"watchware.yaml": $watchware_sha256} end)
      ),
      include_watchware: ($include_watchware == "true"),
      include_example_prefix: ($include_example_prefix == "true")
    },
    artifact: {
      file: $file,
      size: $size,
      sha256: $sha256,
      packages: $packages,
      certs: $certs
    },
    conversion: (
      $stats[0]
      + {
        notes: [
          "Android package ids and certificate fingerprints are normalized; SHA-1 stays in certsSha1 and is never converted to SHA-256.",
          "`com.example.*` indicators are included by default; set INCLUDE_EXAMPLE_PREFIX=false to exclude them.",
          "`watchware.yaml` (mainstream parental-control apps) is excluded by default; set INCLUDE_WATCHWARE=true to mirror it.",
          "Websites and C2 domains and IPs are mirrored for local matching; the builder never resolves or contacts them.",
          "YARA rules, APK hashes, iOS bundle ids and X.509 subject matchers are not mirrored."
        ]
      }
    ),
    compatibility: {
      min_app_version: $min_app_version
    }
  }' > "$OUT_DIR/$SOURCE_INFO_NAME"

SIGNATURE_PATH="$OUT_DIR/$MANIFEST_NAME.sig"
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
  printf 'Generated %s (%s bytes, sha256=%s)\n' "$ARTIFACT_NAME" "$ARTIFACT_SIZE" "$ARTIFACT_SHA256" >&2
  printf 'NOT SIGNED: no signing key was provided.\n' >&2
  printf 'Set FOXHOLE_DNS_SIGNING_KEY or FOXHOLE_DNS_SIGNING_KEY_PEM, or rerun with\n' >&2
  printf 'FOXHOLE_DNS_REQUIRE_SIGNATURE=false for a local unsigned smoke build.\n' >&2
  if [[ -f "$SIGNATURE_PATH" ]]; then
    printf 'The existing %s is now stale and does not match this manifest.\n' \
      "$MANIFEST_NAME.sig" >&2
  fi
  exit 1
else
  printf 'NOT SIGNED: no signing key was provided (unsigned local build).\n' >&2
  printf 'Left %s untouched; the app will reject this output.\n' "$MANIFEST_NAME.sig" >&2
  printf 'This feed is what makes the product accuse an installed app of being stalkerware.\n' >&2
  printf 'Never publish %s without a signature over its exact bytes.\n' "$MANIFEST_NAME" >&2
  if [[ -f "$SIGNATURE_PATH" ]]; then
    printf 'The existing %s is stale and does not match this manifest.\n' \
      "$MANIFEST_NAME.sig" >&2
  fi
fi

printf 'Generated %s (%s bytes, sha256=%s)\n' "$ARTIFACT_NAME" "$ARTIFACT_SIZE" "$ARTIFACT_SHA256"
printf '  packages=%s certs=%s entry_count=%s signed=%s\n' "$PACKAGE_COUNT" "$CERT_COUNT" "$ENTRY_COUNT" "$SIGNED"
printf '  upstream=%s@%s license=CC-BY-4.0 inputs=%s\n' "${SOURCE_REPO%.git}" "$SOURCE_COMMIT" "$INPUT_PATHS"
printf '  conversion stats:\n'
jq -r 'to_entries[] | select(.key != "skipped_samples") | "    \(.key)=\(.value)"' "$STATS_PATH"
