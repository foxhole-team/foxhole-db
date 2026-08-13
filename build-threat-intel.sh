#!/usr/bin/env bash
set -euo pipefail

# Mirrors Association Echap's public stalkerware indicators.
# Consumer contract:
#   manifest name   : foxhole-sentinel-threat-intel
#   manifest format : sentinel-threat-intel-json
#   artifact file   : threat-intel.json   (exact string, checked by the client)
#   artifact body   : {"schema":1,"packages":[...],"certs":[...]}
#   packages        : Android package ids, matched lower-cased + trimmed
#   certs           : lowercase DER certificate SHA-256 without separators

ROOT_DIR="${FOXHOLE_DNS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR}"
WORK_DIR="${WORK_DIR:-$(mktemp -d)}"
SOURCE_REPO="${THREAT_INTEL_SOURCE_REPO:-${SOURCE_REPO:-https://github.com/AssoEchap/stalkerware-indicators.git}}"
SOURCE_REF="${THREAT_INTEL_SOURCE_REF:-${SOURCE_REF:-HEAD}}"
MIN_APP_VERSION="${MIN_APP_VERSION:-1.0.0-beta1}"
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
PYTHON_BIN="${PYTHON_BIN:-python3}"

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
  "$PYTHON_BIN" - "${CONVERT_ARGS[@]}" <<'PYTHON'
"""Convert upstream stalkerware indicators into a FoxHole Sentinel threat-intel bundle.

Only two upstream fields can be carried over safely:

  packages     -> ThreatIntelDocument.packages
  certificates -> NOTHING. Upstream stores SHA-1 fingerprints (40 hex chars,
                  produced by androguard's `cert.sha1_fingerprint`), while the
                  app matches SHA-256 of the DER certificate. SHA-1 -> SHA-256
                  is not a conversion, it is a second preimage. Every such
                  value is skipped and counted.

Anything that does not parse as a valid Android package id is skipped and
counted too. This feed makes the product tell a user that a named app on their
phone is stalkerware, so guessing is never the right move.
"""

import json
import os
import re
import sys

import yaml

# AOSP package-id grammar.
PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
# Certificate fingerprints the app can match.
CERT_SHA256_RE = re.compile(r"[0-9a-f]{64}")
# Preserve upstream SHA-1 separately from SHA-256.
CERT_SHA1_RE = re.compile(r"[0-9a-f]{40}")
# Accept exact hostnames only; broad matches risk false accusations.
DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")
IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
IPV6_RE = re.compile(r"[0-9a-f:]{3,45}")

INCLUDE_EXAMPLE_PREFIX = os.environ.get("INCLUDE_EXAMPLE_PREFIX") == "true"

packages = set()
certs = set()
certs_sha1 = set()
domains = set()
ips = set()


def add_domain(raw, entry_name):
    stats["domain_values_seen"] += 1
    value = str(raw).strip().lower()
    # Normalize URLs to hostnames.
    value = value.split("//")[-1].split("/")[0].split("?")[0].strip().strip(".")
    if value.startswith("*."):
        value = value[2:]
    value = value.split(":")[0]
    if not value or len(value) > 253 or not DOMAIN_RE.fullmatch(value):
        stats["domain_values_skipped_invalid"] += 1
        note_skip("invalid-domain", entry_name, raw)
        return
    if value.count(".") < 1:
        stats["domain_values_skipped_invalid"] += 1
        note_skip("bare-tld", entry_name, raw)
        return
    domains.add(value)


def add_ip(raw, entry_name):
    stats["ip_values_seen"] += 1
    value = str(raw).strip().lower()
    if IPV4_RE.fullmatch(value):
        octets = value.split(".")
        if all(o.isdigit() and 0 <= int(o) <= 255 and (o == "0" or not o.startswith("0")) for o in octets):
            ips.add(value)
            return
    elif ":" in value and IPV6_RE.fullmatch(value):
        ips.add(value)
        return
    stats["ip_values_skipped_invalid"] += 1
    note_skip("invalid-ip", entry_name, raw)
stats = {
    "entries_total": 0,
    "entries_without_package_id": 0,
    "package_values_seen": 0,
    "package_values_skipped_invalid": 0,
    "package_values_skipped_example_prefix": 0,
    "cert_values_seen": 0,
    "cert_sha1_emitted": 0,
    "domain_values_seen": 0,
    "domain_values_skipped_invalid": 0,
    "ip_values_seen": 0,
    "ip_values_skipped_invalid": 0,
    "cert_values_skipped_sha1_not_sha256": 0,
    "cert_values_skipped_other_format": 0,
    "entries_with_certificate_subject_matchers_only": 0,
    "ios_bundle_values_ignored": 0,
    "skipped_samples": [],
}


def note_skip(kind, entry_name, value):
    if len(stats["skipped_samples"]) < 40:
        stats["skipped_samples"].append(
            {"kind": kind, "entry": entry_name, "value": str(value)[:120]}
        )


for path in sys.argv[1:]:
    with open(path, "r", encoding="utf-8") as handle:
        documents = yaml.safe_load(handle) or []
    for entry in documents:
        if not isinstance(entry, dict):
            stats["entries_total"] += 1
            note_skip("entry-not-a-mapping", "?", entry)
            continue
        stats["entries_total"] += 1
        name = str(entry.get("name", "?"))

        raw_packages = entry.get("packages") or []
        if not raw_packages:
            stats["entries_without_package_id"] += 1
            note_skip("entry-without-package-id", name, "")
        for raw in raw_packages:
            stats["package_values_seen"] += 1
            value = str(raw).strip()
            if not PACKAGE_RE.fullmatch(value) or len(value) > 255:
                stats["package_values_skipped_invalid"] += 1
                note_skip("invalid-package-id", name, raw)
                continue
            # Match scorer normalization and keep output deterministic.
            value = value.lower()
            if value.startswith("com.example.") and not INCLUDE_EXAMPLE_PREFIX:
                stats["package_values_skipped_example_prefix"] += 1
                note_skip("package-default-template-prefix", name, raw)
                continue
            packages.add(value)

        raw_certs = entry.get("certificates") or []
        for raw in raw_certs:
            stats["cert_values_seen"] += 1
            value = str(raw).strip().replace(":", "").replace(" ", "").lower()
            if CERT_SHA256_RE.fullmatch(value):
                certs.add(value)
            elif CERT_SHA1_RE.fullmatch(value):
                certs_sha1.add(value)
                note_skip("cert-sha1-not-sha256", name, raw)
            else:
                stats["cert_values_skipped_other_format"] += 1
                note_skip("cert-unknown-format", name, raw)

        # Both distribution and C2 destinations can match live flows.
        for raw in entry.get("websites") or []:
            add_domain(raw, name)
        c2 = entry.get("c2") or {}
        if isinstance(c2, dict):
            for raw in c2.get("domains") or []:
                add_domain(raw, name)
            for raw in c2.get("ips") or []:
                add_ip(raw, name)

        # The app cannot match X.509 subject fields.
        if entry.get("certificate_cname_re") or entry.get("certificate_organizations"):
            stats["entries_with_certificate_subject_matchers_only"] += 1

        stats["ios_bundle_values_ignored"] += len(entry.get("ios_bundles") or [])

document = {
    "schema": 3,
    "packages": sorted(packages),
    "certs": sorted(certs),
    "certsSha1": sorted(certs_sha1),
    "domains": sorted(domains),
    "ips": sorted(ips),
}

with open(os.environ["ARTIFACT_PATH"], "w", encoding="utf-8") as handle:
    json.dump(document, handle, indent=2, ensure_ascii=False)
    handle.write("\n")

stats["packages_emitted"] = len(document["packages"])
stats["certs_emitted"] = len(document["certs"])
stats["cert_sha1_emitted"] = len(document["certsSha1"])
stats["domains_emitted"] = len(document["domains"])
stats["ips_emitted"] = len(document["ips"])
with open(os.environ["STATS_PATH"], "w", encoding="utf-8") as handle:
    json.dump(stats, handle, indent=2, ensure_ascii=False)
PYTHON

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
          "Only Android package ids and Android signing-certificate SHA-256 hashes are mirrored.",
          "Upstream `certificates` are SHA-1 fingerprints; the app matches SHA-256 of the DER signing certificate, so they are skipped rather than guessed.",
          "`com.example.*` indicators are excluded by default (Android Studio default template prefix, high benign-collision risk); set INCLUDE_EXAMPLE_PREFIX=true to mirror them.",
          "`watchware.yaml` (mainstream parental-control apps) is excluded by default; set INCLUDE_WATCHWARE=true to mirror it.",
          "Network indicators (websites, c2) belong to the DNS rule set pipeline and are not mirrored here.",
          "YARA rules and APK sample hashes are not mirrored: the app has no engine for them."
        ]
      }
    ),
    compatibility: {
      min_app_version: $min_app_version
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
