#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/public}"
SPEC_DIR="${FOXHOLE_DNS_CATEGORY_SPEC_DIR:-$ROOT_DIR/dns-category-sources}"
SOURCE_ROOT="${FOXHOLE_DNS_CATEGORY_SOURCE_ROOT:-}"
COMPILER="${FOXCORE_DNS_COMPILE_BIN:?Provide the source-built category compiler in Docker}"
PUBLIC_KEY="${FOXHOLE_DNS_PUBLIC_KEY:-$ROOT_DIR/manifest.public.pem}"
REQUIRE_SIGNATURE="${FOXHOLE_DNS_REQUIRE_SIGNATURE:-true}"
SIGNING_KEY_PATH="${FOXHOLE_DNS_SIGNING_KEY:-}"
SIGNING_KEY_PEM="${FOXHOLE_DNS_SIGNING_KEY_PEM:-}"
unset FOXHOLE_DNS_SIGNING_KEY_PEM
TEMP_KEY_PATH=""
WORK_PARENT="${WORK_DIR:-${TMPDIR:-/tmp}}"
mkdir -p "$WORK_PARENT"
OWNED_WORK_DIR="$(mktemp -d "$WORK_PARENT/foxhole-dns-categories.XXXXXXXX")"
cleanup() {
  if [[ -n "$TEMP_KEY_PATH" ]]; then
    rm -f "$TEMP_KEY_PATH"
  fi
  if [[ "${KEEP_WORK_DIR:-false}" != "true" && -d "$OWNED_WORK_DIR" ]]; then
    rm -rf "$OWNED_WORK_DIR"
  fi
}
trap cleanup EXIT

if [[ -z "$SOURCE_ROOT" ]]; then
  SOURCE_ROOT="$OWNED_WORK_DIR/sources"
  python3 "$ROOT_DIR/fetch-dns-category-sources.py" --spec-dir "$SPEC_DIR" --output "$SOURCE_ROOT"
fi
[[ "$REQUIRE_SIGNATURE" == "true" || "$REQUIRE_SIGNATURE" == "false" ]]
[[ -x "$COMPILER" && -s "$PUBLIC_KEY" ]]
KEY_SHA256="$(openssl pkey -pubin -in "$PUBLIC_KEY" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
if [[ "$REQUIRE_SIGNATURE" == "true" ]]; then
  if [[ -n "$SIGNING_KEY_PEM" ]]; then
    TEMP_KEY_PATH="$OWNED_WORK_DIR/manifest.private.pem"
    (umask 077; printf '%s\n' "$SIGNING_KEY_PEM" > "$TEMP_KEY_PATH")
    SIGNING_KEY_PATH="$TEMP_KEY_PATH"
  fi
  unset SIGNING_KEY_PEM
  [[ -n "$SIGNING_KEY_PATH" && -s "$SIGNING_KEY_PATH" ]]
  signer_hash="$(openssl pkey -in "$SIGNING_KEY_PATH" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
  [[ "$signer_hash" == "$KEY_SHA256" ]]
fi
GENERATED="${GENERATED_AT_UNIX:-$(date -u +%s)}"
SEQUENCE_VALUE="${SEQUENCE:-$GENERATED}"
VALIDITY="${MANIFEST_VALIDITY_SECONDS:-2592000}"
EXPIRES="$(python3 -c 'import sys; print(int(sys.argv[1]) + int(sys.argv[2]))' "$GENERATED" "$VALIDITY")"

for variant in normal-medium normal-full pro-medium pro-full; do
  spec="$SPEC_DIR/$variant.json"
  [[ -s "$spec" ]]
  candidate="$OWNED_WORK_DIR/$variant"
  python3 "$ROOT_DIR/dns-categories-manifest.py" \
    --source-spec "$spec" --source-root "$SOURCE_ROOT" --compiler "$COMPILER" \
    --output "$candidate" --key-sha256 "$KEY_SHA256" \
    --sequence "$SEQUENCE_VALUE" --generated "$GENERATED" --expires "$EXPIRES"
  if [[ "$REQUIRE_SIGNATURE" == "true" ]]; then
    openssl dgst -sha256 -sign "$SIGNING_KEY_PATH" \
      -out "$candidate/manifest.json.sig" "$candidate/manifest.json"
    openssl dgst -sha256 -verify "$PUBLIC_KEY" \
      -signature "$candidate/manifest.json.sig" "$candidate/manifest.json" >/dev/null
  fi
done

for variant in normal-medium normal-full pro-medium pro-full; do
  candidate="$OWNED_WORK_DIR/$variant"
  destination="$OUT_DIR/dns-categories/$variant"
  mkdir -p "$destination"
  cp "$candidate/manifest.json" "$candidate/dns-categories.fhds" "$candidate/dns-categories.fhds.sha256" "$destination/"
  if [[ "$REQUIRE_SIGNATURE" == "true" ]]; then
    cp "$candidate/manifest.json.sig" "$destination/"
  else
    rm -f "$destination/manifest.json.sig"
  fi
  printf 'Built categorized DNS variant %s\n' "$variant"
done
