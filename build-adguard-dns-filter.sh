#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${FOXHOLE_DNS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
SOURCE_REPO="${ADGUARD_SOURCE_REPO:-${SOURCE_REPO:-https://github.com/AdguardTeam/AdGuardSDNSFilter.git}}"
SOURCE_REF="${ADGUARD_SOURCE_REF:-${SOURCE_REF:-HEAD}}"
FOXCORE_DNS_COMPILE_BIN="${FOXCORE_DNS_COMPILE_BIN:-foxcore-dns-compile}"
FOXCORE_ROOT="${FOXCORE_ROOT:-}"
CARGO_BIN="${CARGO_BIN:-cargo}"
FILTER_CATEGORY="${FILTER_CATEGORY:-ads}"
ALLOWLIST_FILE="${ALLOWLIST_FILE:-$ROOT_DIR/adguard-vpn-compatibility-allowlist.txt}"
MIN_APP_VERSION="${MIN_APP_VERSION:-0.0.1}"
FILTER_NAME="${FILTER_NAME:-adguard-dns-filter.fhds}"
ARTIFACT_FORMAT="${ARTIFACT_FORMAT:-foxhole-dns-fst-v1}"
RULE_SET_NAME="${RULE_SET_NAME:-foxhole-adguard-dns-filter}"
MANIFEST_NAME="${MANIFEST_NAME:-manifest.json}"
SOURCE_INFO_NAME="${SOURCE_INFO_NAME:-source-info.json}"
# Rust rejects unknown fields while Kotlin ignores them; add fields only with a schema bump.
MANIFEST_SCHEMA="${MANIFEST_SCHEMA:-2}"
CORE_SCHEMA="${CORE_SCHEMA:-1}"
MANIFEST_VALIDITY_SECONDS="${MANIFEST_VALIDITY_SECONDS:-2592000}"
PUBLIC_KEY_PATH="${FOXHOLE_DNS_PUBLIC_KEY:-$ROOT_DIR/manifest.public.pem}"
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

need git
need jq
need openssl
need sha256sum

COMPILER_PATH=""
resolve_compiler() {
  if [[ -x "$FOXCORE_DNS_COMPILE_BIN" ]]; then
    COMPILER_PATH="$(cd "$(dirname "$FOXCORE_DNS_COMPILE_BIN")" && pwd)/$(basename "$FOXCORE_DNS_COMPILE_BIN")"
    return
  fi
  if command -v "$FOXCORE_DNS_COMPILE_BIN" >/dev/null 2>&1; then
    COMPILER_PATH="$(command -v "$FOXCORE_DNS_COMPILE_BIN")"
    return
  fi
  if [[ -n "$FOXCORE_ROOT" ]]; then
    if [[ ! -f "$FOXCORE_ROOT/Cargo.toml" ]]; then
      printf 'FOXCORE_ROOT does not contain a Cargo workspace: %s\n' "$FOXCORE_ROOT" >&2
      exit 1
    fi
    need "$CARGO_BIN"
    printf 'Building foxcore-dns-compile from %s\n' "$FOXCORE_ROOT" >&2
    (
      cd "$FOXCORE_ROOT"
      "$CARGO_BIN" build --release -p foxcore-route --bin foxcore-dns-compile
    )
    COMPILER_PATH="${CARGO_TARGET_DIR:-$FOXCORE_ROOT/target}/release/foxcore-dns-compile"
    if [[ ! -x "$COMPILER_PATH" ]]; then
      printf 'Build succeeded but binary is missing: %s\n' "$COMPILER_PATH" >&2
      exit 1
    fi
    return
  fi
  cat >&2 <<EOF
Missing the FoxCore DNS rule-set compiler.

Provide it in one of these ways:
  * FOXCORE_DNS_COMPILE_BIN=/path/to/foxcore-dns-compile  (prebuilt binary)
  * put foxcore-dns-compile on PATH
  * FOXCORE_ROOT=/path/to/foxhole-guard-rust-core         (built here with:
    cargo build --release -p foxcore-route --bin foxcore-dns-compile)
EOF
  exit 1
}
resolve_compiler
COMPILER_NAME="$(basename "$COMPILER_PATH")"

ALLOWLIST_ARGS=()
ALLOWLIST_NAME=""
if [[ -n "$ALLOWLIST_FILE" ]]; then
  if [[ ! -s "$ALLOWLIST_FILE" ]]; then
    printf 'Missing compatibility allowlist: %s\n' "$ALLOWLIST_FILE" >&2
    printf 'Set ALLOWLIST_FILE="" to compile without an allowlist.\n' >&2
    exit 1
  fi
  ALLOWLIST_ARGS=(--allowlist "$ALLOWLIST_FILE")
  ALLOWLIST_NAME="$(basename "$ALLOWLIST_FILE")"
fi

run_yarn() {
  if command -v yarn >/dev/null 2>&1; then
    yarn "$@"
  else
    corepack yarn "$@"
  fi
}

mkdir -p "$OUT_DIR" "$WORK_DIR"

SOURCE_DIR="$WORK_DIR/AdGuardSDNSFilter"
if [[ "$SOURCE_REF" == "HEAD" ]]; then
  git clone --depth 1 "$SOURCE_REPO" "$SOURCE_DIR"
else
  git init "$SOURCE_DIR"
  git -C "$SOURCE_DIR" remote add origin "$SOURCE_REPO"
  git -C "$SOURCE_DIR" fetch --depth 1 origin "$SOURCE_REF"
  git -C "$SOURCE_DIR" checkout --detach FETCH_HEAD
fi

SOURCE_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
SOURCE_BRANCH="$(git -C "$SOURCE_DIR" rev-parse --abbrev-ref HEAD)"
if [[ "$SOURCE_BRANCH" == "HEAD" ]]; then
  SOURCE_BRANCH="$SOURCE_REF"
fi
SOURCE_REPO_URL="${SOURCE_REPO%.git}"

if [[ -f "$SOURCE_DIR/package.json" ]]; then
  need node
  if ! command -v yarn >/dev/null 2>&1; then
    need corepack
  fi
  (
    cd "$SOURCE_DIR"
    run_yarn install --frozen-lockfile
    run_yarn run build
  )
fi

INPUT_FILE="$SOURCE_DIR/Filters/filter.txt"
if [[ ! -s "$INPUT_FILE" ]]; then
  printf 'Missing built AdGuard input filter: %s\n' "$INPUT_FILE" >&2
  exit 1
fi

ARTIFACT_PATH="$OUT_DIR/$FILTER_NAME"
COMPILE_LOG="$WORK_DIR/foxcore-dns-compile.log"
"$COMPILER_PATH" \
  --input "$INPUT_FILE" \
  --output "$ARTIFACT_PATH" \
  --category "$FILTER_CATEGORY" \
  ${ALLOWLIST_ARGS[@]+"${ALLOWLIST_ARGS[@]}"} 2>&1 | tee "$COMPILE_LOG"

BLOCK_ENTRIES="$(awk '/^compiled [0-9]+ block and [0-9]+ allow/ {print $2; exit}' "$COMPILE_LOG")"
ALLOW_ENTRIES="$(awk '/^compiled [0-9]+ block and [0-9]+ allow/ {print $5; exit}' "$COMPILE_LOG")"
if [[ ! "$BLOCK_ENTRIES" =~ ^[0-9]+$ || ! "$ALLOW_ENTRIES" =~ ^[0-9]+$ ]]; then
  printf 'Could not read entry counts from %s output.\n' "$COMPILER_NAME" >&2
  exit 1
fi

if [[ ! -s "$ARTIFACT_PATH" ]]; then
  printf 'Compiler produced no artifact: %s\n' "$ARTIFACT_PATH" >&2
  exit 1
fi

INPUT_SHA256="$(sha256sum "$INPUT_FILE" | awk '{print $1}')"
ARTIFACT_SHA256="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
ARTIFACT_SIZE="$(wc -c < "$ARTIFACT_PATH" | tr -d ' ')"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
GENERATED_AT_UNIX="$(date -u +%s)"
EXPIRES_AT_UNIX="$((GENERATED_AT_UNIX + MANIFEST_VALIDITY_SECONDS))"
# Sequence must increase across published manifests.
SEQUENCE="${SEQUENCE:-$GENERATED_AT_UNIX}"

printf '%s  %s\n' "$ARTIFACT_SHA256" "$FILTER_NAME" > "$OUT_DIR/$FILTER_NAME.sha256"

# Resolve the key before binding its digest into the manifest.
TEMP_KEY_PATH=""
if [[ -n "$SIGNING_KEY_PEM" ]]; then
  TEMP_KEY_PATH="$WORK_DIR/manifest.private.pem"
  # Limit private-key permissions without changing the caller's umask.
  (
    umask 077
    printf '%s\n' "$SIGNING_KEY_PEM" > "$TEMP_KEY_PATH"
  )
  SIGNING_KEY_PATH="$TEMP_KEY_PATH"
fi

public_key_der_sha256() {
  openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
}

private_key_der_sha256() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}'
}

KEY_SHA256=""
if [[ -n "$SIGNING_KEY_PATH" ]]; then
  KEY_SHA256="$(private_key_der_sha256 "$SIGNING_KEY_PATH")"
  if [[ ! "$KEY_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'Could not derive a public key from the signing key.\n' >&2
    exit 1
  fi
  if [[ -s "$PUBLIC_KEY_PATH" ]]; then
    PUBLISHED_KEY_SHA256="$(public_key_der_sha256 "$PUBLIC_KEY_PATH")"
    if [[ "$KEY_SHA256" != "$PUBLISHED_KEY_SHA256" ]]; then
      printf 'Signing key does not match %s.\n' "$PUBLIC_KEY_PATH" >&2
      printf 'Apps embed that public key and would reject every signed manifest.\n' >&2
      exit 1
    fi
  fi
elif [[ -s "$PUBLIC_KEY_PATH" ]]; then
  KEY_SHA256="$(public_key_der_sha256 "$PUBLIC_KEY_PATH")"
fi
if [[ ! "$KEY_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'Missing or unreadable public key: %s\n' "$PUBLIC_KEY_PATH" >&2
  printf 'manifest.key_sha256 cannot be computed without it.\n' >&2
  exit 1
fi

# Keep this shape identical to foxcore-route::ruleset::Manifest.
jq -n \
  --arg name "$RULE_SET_NAME" \
  --arg format "$ARTIFACT_FORMAT" \
  --arg key_sha256 "$KEY_SHA256" \
  --arg source_repo "$SOURCE_REPO_URL" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg input_sha256 "$INPUT_SHA256" \
  --arg file "$FILTER_NAME" \
  --arg sha256 "$ARTIFACT_SHA256" \
  --argjson schema "$MANIFEST_SCHEMA" \
  --argjson core_schema "$CORE_SCHEMA" \
  --argjson sequence "$SEQUENCE" \
  --argjson generated_at_unix "$GENERATED_AT_UNIX" \
  --argjson expires_at_unix "$EXPIRES_AT_UNIX" \
  --argjson size "$ARTIFACT_SIZE" \
  --argjson block_entries "$BLOCK_ENTRIES" \
  --argjson allow_entries "$ALLOW_ENTRIES" \
  '{
    schema: $schema,
    name: $name,
    format: $format,
    sequence: $sequence,
    generated_at_unix: $generated_at_unix,
    expires_at_unix: $expires_at_unix,
    key_sha256: $key_sha256,
    source: {
      name: "AdGuardSDNSFilter",
      repo: $source_repo,
      commit: $source_commit,
      license: "GPL-3.0",
      input_path: "Filters/filter.txt",
      input_sha256: $input_sha256
    },
    artifact: {
      file: $file,
      size: $size,
      sha256: $sha256,
      block_entries: $block_entries,
      allow_entries: $allow_entries
    },
    compatibility: {
      core_schema: $core_schema
    }
  }' > "$OUT_DIR/$MANIFEST_NAME"

jq -n \
  --arg generated_at "$GENERATED_AT" \
  --arg format "$ARTIFACT_FORMAT" \
  --arg source_repo "$SOURCE_REPO_URL" \
  --arg source_branch "$SOURCE_BRANCH" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg input_sha256 "$INPUT_SHA256" \
  --arg compiler "$COMPILER_NAME" \
  --arg category "$FILTER_CATEGORY" \
  --arg allowlist "$ALLOWLIST_NAME" \
  --arg file "$FILTER_NAME" \
  --arg sha256 "$ARTIFACT_SHA256" \
  --arg min_app_version "$MIN_APP_VERSION" \
  --argjson core_schema "$CORE_SCHEMA" \
  --argjson sequence "$SEQUENCE" \
  --argjson size "$ARTIFACT_SIZE" \
  --argjson block_entries "$BLOCK_ENTRIES" \
  --argjson allow_entries "$ALLOW_ENTRIES" \
  '{
    schema: 1,
    format: $format,
    generated_at: $generated_at,
    sequence: $sequence,
    source: {
      name: "AdGuardSDNSFilter",
      repo: $source_repo,
      branch: $source_branch,
      commit: $source_commit,
      input_path: "Filters/filter.txt",
      input_sha256: $input_sha256,
      license: "GPL-3.0"
    },
    compiler: {
      binary: $compiler,
      category: $category,
      allowlist: (if $allowlist == "" then null else $allowlist end)
    },
    artifact: {
      file: $file,
      size: $size,
      sha256: $sha256,
      block_entries: $block_entries,
      allow_entries: $allow_entries
    },
    compatibility: {
      core_schema: $core_schema,
      min_app_version: $min_app_version
    }
  }' > "$OUT_DIR/$SOURCE_INFO_NAME"

SIGNATURE_PATH="$OUT_DIR/$MANIFEST_NAME.sig"
SIGNED="false"
if [[ -n "$SIGNING_KEY_PATH" ]]; then
  openssl dgst -sha256 -sign "$SIGNING_KEY_PATH" -out "$SIGNATURE_PATH" "$OUT_DIR/$MANIFEST_NAME"
  if [[ -s "$PUBLIC_KEY_PATH" ]]; then
    openssl dgst -sha256 -verify "$PUBLIC_KEY_PATH" -signature "$SIGNATURE_PATH" \
      "$OUT_DIR/$MANIFEST_NAME" >/dev/null
  fi
  SIGNED="true"
elif [[ "$REQUIRE_SIGNATURE" == "true" ]]; then
  printf 'Generated %s (%s bytes, sha256=%s)\n' "$FILTER_NAME" "$ARTIFACT_SIZE" "$ARTIFACT_SHA256" >&2
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
  if [[ -f "$SIGNATURE_PATH" ]]; then
    printf 'The existing %s is stale and does not match this manifest.\n' \
      "$MANIFEST_NAME.sig" >&2
  fi
fi

printf 'Generated %s (%s bytes, sha256=%s, block=%s, allow=%s, signed=%s)\n' \
  "$FILTER_NAME" "$ARTIFACT_SIZE" "$ARTIFACT_SHA256" \
  "$BLOCK_ENTRIES" "$ALLOW_ENTRIES" "$SIGNED"
