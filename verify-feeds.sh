#!/usr/bin/env bash
# Offline acceptance check for a built public/ directory.
# Usage: ./verify-feeds.sh [directory] (default: ./public)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${1:-${VERIFY_DIR:-$ROOT_DIR/public}}"
PUBLIC_KEY="${FOXHOLE_DNS_PUBLIC_KEY:-$ROOT_DIR/manifest.public.pem}"
PUBLISHED_FILES="$ROOT_DIR/.github/published-files.txt"
VERIFY_SIGNATURES="${FOXHOLE_VERIFY_SIGNATURES:-true}"
# Reject stale feeds before publication.
MAX_AGE_DAYS="${MAX_AGE_DAYS:-45}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  }
}
need jq
need openssl
need sha256sum

FAILURES=0
fail() {
  printf '  FAIL  %s\n' "$1" >&2
  FAILURES=$((FAILURES + 1))
}
pass() { printf '  ok    %s\n' "$1"; }

if [[ ! -d "$DIR" ]]; then
  printf 'Nothing to verify: %s does not exist.\n' "$DIR" >&2
  printf 'Build the feeds first (see the README "Local build" section).\n' >&2
  exit 1
fi
if [[ ! -s "$PUBLIC_KEY" ]]; then
  printf 'Missing public key: %s\n' "$PUBLIC_KEY" >&2
  exit 1
fi
if [[ ! -s "$PUBLISHED_FILES" ]]; then
  printf 'Missing published-file contract: %s\n' "$PUBLISHED_FILES" >&2
  exit 1
fi
if [[ "$VERIFY_SIGNATURES" != "true" && "$VERIFY_SIGNATURES" != "false" ]]; then
  printf 'FOXHOLE_VERIFY_SIGNATURES must be true or false.\n' >&2
  exit 1
fi

if find "$DIR" ! -type d ! -type f -print -quit | grep -q .; then
  printf 'Public output contains a symlink or special file.\n' >&2
  exit 1
fi
expected_files() {
  if [[ "$VERIFY_SIGNATURES" == "true" ]]; then
    cat "$PUBLISHED_FILES"
  else
    grep -v '\.sig$' "$PUBLISHED_FILES"
  fi
}
actual_files() {
  (cd "$DIR" && find . -type f -print | sed 's#^\./##' | LC_ALL=C sort)
}
if ! diff -u <(expected_files) <(actual_files); then
  printf 'Public output does not match the exact published-file contract.\n' >&2
  exit 1
fi

now_unix="$(date -u +%s)"
max_age_seconds=$((MAX_AGE_DAYS * 86400))

# DNS uses generated_at_unix; the other feeds use generated_at.
manifest_age() {
  local file="$1" stamp iso
  stamp="$(jq -r '.generated_at_unix // empty' "$file")"
  if [[ -z "$stamp" ]]; then
    iso="$(jq -r '.generated_at // empty' "$file")"
    [[ -n "$iso" ]] || return 1
    stamp="$(date -u -d "$iso" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$iso" +%s 2>/dev/null || true)"
    [[ -n "$stamp" ]] || return 1
  fi
  printf '%s\n' $((now_unix - stamp))
}

check_feed() {
  local label="$1" manifest_name="$2" want_schema="$3" want_format="$4" want_name="$5" jq_artifacts="$6" want_files="$7"
  local manifest="$DIR/$manifest_name"
  printf '%s (%s)\n' "$label" "$manifest_name"

  if [[ ! -s "$manifest" ]]; then
    fail "$manifest_name is missing — this feed was never published by this run"
    return
  fi
  if ! jq -e . "$manifest" >/dev/null 2>&1; then
    fail "$manifest_name is not valid JSON"
    return
  fi

  local got
  got="$(jq -r '.schema // "absent"' "$manifest")"
  [[ "$got" == "$want_schema" ]] || fail "$manifest_name schema is $got, the app expects $want_schema"
  got="$(jq -r '.format // "absent"' "$manifest")"
  [[ "$got" == "$want_format" ]] || fail "$manifest_name format is '$got', the app expects '$want_format'"
  got="$(jq -r '.name // "absent"' "$manifest")"
  [[ "$got" == "$want_name" ]] || fail "$manifest_name name is '$got', the app expects '$want_name'"

  local got_files
  got_files="$(jq -r "$jq_artifacts" "$manifest" | cut -f1 | LC_ALL=C sort | paste -sd, -)"
  [[ "$got_files" == "$want_files" ]] || fail "$manifest_name names '$got_files', expected '$want_files'"

  if [[ "$manifest_name" == "manifest.json" ]]; then
    local declared_key actual_key
    declared_key="$(jq -r '.key_sha256 // "absent"' "$manifest")"
    actual_key="$(openssl pkey -pubin -in "$PUBLIC_KEY" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
    [[ "$declared_key" == "$actual_key" ]] || fail "$manifest_name is bound to a different public key"
  fi

  # Structural checks run first so this local publisher gate reports all candidate failures at once.
  if [[ "$VERIFY_SIGNATURES" == "false" ]]; then
    pass "$manifest_name is an unsigned build candidate"
  elif [[ ! -s "$manifest.sig" ]]; then
    fail "$manifest_name.sig is missing — an unsigned manifest is rejected by the app"
  elif openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$manifest.sig" "$manifest" >/dev/null 2>&1; then
    pass "$manifest_name.sig verifies against $(basename "$PUBLIC_KEY")"
  else
    fail "$manifest_name.sig does not verify against $(basename "$PUBLIC_KEY")"
  fi

  # Only the DNS manifest carries an expiry.
  local expires
  expires="$(jq -r '.expires_at_unix // empty' "$manifest")"
  if [[ -n "$expires" ]]; then
    if ((expires <= now_unix)); then
      fail "$manifest_name is already expired ($(((now_unix - expires) / 86400)) days ago)"
    else
      pass "$manifest_name is valid for another $(((expires - now_unix) / 86400)) days"
    fi
  fi

  local age
  if age="$(manifest_age "$manifest")"; then
    if ((age > max_age_seconds)); then
      fail "$manifest_name was generated $((age / 86400)) days ago (limit ${MAX_AGE_DAYS})"
    else
      pass "$manifest_name is $((age / 86400)) days old"
    fi
  else
    fail "$manifest_name has no readable generation timestamp"
  fi

  # Require manifest size and digest parity.
  local file size sha actual_size actual_sha
  while IFS=$'\t' read -r file size sha; do
    [[ -n "$file" ]] || continue
    if [[ ! -f "$DIR/$file" ]]; then
      fail "$manifest_name names $file, which is not in $DIR"
      continue
    fi
    actual_size="$(wc -c <"$DIR/$file" | tr -d ' ')"
    actual_sha="$(sha256sum "$DIR/$file" | awk '{print $1}')"
    if [[ "$actual_size" != "$size" ]]; then
      fail "$file is $actual_size bytes, the manifest says $size"
    elif [[ "$actual_sha" != "$sha" ]]; then
      fail "$file digest is $actual_sha, the manifest says $sha"
    else
      pass "$file matches its manifest entry ($size bytes)"
    fi
  done < <(jq -r "$jq_artifacts" "$manifest")
}

printf 'Verifying %s\n\n' "$DIR"

check_feed "DNS rule set" manifest.json 2 foxhole-dns-fst-v1 foxhole-adguard-dns-filter \
  '.artifact | [.file, (.size|tostring), .sha256] | @tsv' \
  'adguard-dns-filter.fhds'
printf '\n'
check_feed "Tor bridges" bridges-manifest.json 1 tor-bridges-json foxhole-tor-bridges \
  '.artifact | [.file, (.size|tostring), .sha256] | @tsv' \
  'bridges.json'
printf '\n'
check_feed "FoxHole Sentinel threat intel" threat-intel-manifest.json 1 sentinel-threat-intel-json foxhole-sentinel-threat-intel \
  '.artifact | [.file, (.size|tostring), .sha256] | @tsv' \
  'threat-intel.json'
printf '\n'
check_feed "Geo database" geoip-manifest.json 1 dbip-country-csv foxhole-geoip \
  '.artifacts[] | [.file, (.size|tostring), .sha256] | @tsv' \
  'dbip-country-ipv4.csv,dbip-country-ipv6.csv'
printf '\n'
check_feed "TLS fingerprint tables" fingerprint-manifest.json 1 tls-fingerprint-tables-json foxhole-tls-fingerprints \
  '.artifact | [.file, (.size|tostring), .sha256] | @tsv' \
  'fingerprints.json'

# Match the app's per-profile digest check before the candidate is signed.
verify_fingerprint_profiles() {
  local bundle="$DIR/fingerprints.json" count declared derived name
  [[ -s "$bundle" ]] || return 0
  count="$(jq -r '.profiles | length' "$bundle" 2>/dev/null || echo 0)"
  if [[ "$count" == "0" ]]; then
    fail "fingerprints.json carries no profiles"
    return
  fi
  local index=0 bad=0
  while ((index < count)); do
    name="$(jq -r --argjson i "$index" '.profiles[$i].name // "?"' "$bundle")"
    declared="$(jq -r --argjson i "$index" '.profiles[$i].fingerprint_sha256 // empty' "$bundle")"
    derived="$(jq -cSa --argjson i "$index" '.profiles[$i].fingerprint' "$bundle" |
      tr -d '\n' | sha256sum | awk '{print $1}')"
    if [[ -z "$declared" ]]; then
      fail "fingerprints.json profile $name carries no fingerprint_sha256"
      bad=$((bad + 1))
    elif [[ "$declared" != "$derived" ]]; then
      fail "fingerprints.json profile $name hashes to $derived, it declares $declared"
      bad=$((bad + 1))
    fi
    index=$((index + 1))
  done
  ((bad > 0)) || pass "all $count fingerprint profiles re-derive their own digest"
}
verify_fingerprint_profiles

printf '\n'
if ((FAILURES > 0)); then
  printf '%d check(s) failed. This output must not be published.\n' "$FAILURES" >&2
  exit 1
fi
if [[ "$VERIFY_SIGNATURES" == "true" ]]; then
  printf 'All five feeds are present, signed and self-consistent.\n'
else
  printf 'All five unsigned build candidates are present and self-consistent.\n'
fi
