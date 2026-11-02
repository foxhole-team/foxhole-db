"""Convert upstream indicators without guessing missing or malformed values.

SHA-1 certificate fingerprints remain separate from SHA-256, and network
destinations are normalized for local matching without contacting them.
"""

import ipaddress
import json
import os
import re
import sys

PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
CERT_SHA256_RE = re.compile(r"[0-9a-f]{64}")
CERT_SHA1_RE = re.compile(r"[0-9a-f]{40}")
# Accept exact hostnames only; broad matches risk false accusations.
DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")

INCLUDE_EXAMPLE_PREFIX = os.environ.get("INCLUDE_EXAMPLE_PREFIX") == "true"

packages = set()
certs = set()
certs_sha1 = set()
domains = set()
ips = set()


def add_domain(raw, entry_name):
    stats["domain_values_seen"] += 1
    value = str(raw).strip().lower()
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
    value = str(raw).strip()
    try:
        if "%" in value:
            raise ValueError("scoped addresses are not portable indicators")
        address = ipaddress.ip_address(value)
    except ValueError:
        stats["ip_values_skipped_invalid"] += 1
        note_skip("invalid-ip", entry_name, raw)
        return
    ips.add(address.compressed.lower())
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


def convert(paths):
    """Convert one batch with the existing one-shot module state."""
    import yaml

    for path in paths:
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
                else:
                    stats["cert_values_skipped_other_format"] += 1
                    note_skip("cert-unknown-format", name, raw)

            # Product websites and C2 destinations can match live flows.
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

    stats["packages_emitted"] = len(document["packages"])
    stats["certs_emitted"] = len(document["certs"])
    stats["cert_sha1_emitted"] = len(document["certsSha1"])
    stats["domains_emitted"] = len(document["domains"])
    stats["ips_emitted"] = len(document["ips"])
    return document, stats


def main(argv=None):
    document, statistics = convert(sys.argv[1:] if argv is None else argv)
    with open(os.environ["ARTIFACT_PATH"], "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    with open(os.environ["STATS_PATH"], "w", encoding="utf-8") as handle:
        json.dump(statistics, handle, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
