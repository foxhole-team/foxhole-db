#!/usr/bin/env python3
"""Compare a verified candidate with Pages without treating build clocks as data changes."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request


MANIFESTS = (
    "manifest.json",
    "threat-intel-manifest.json",
    "bridges-manifest.json",
    "geoip-manifest.json",
    "fingerprint-manifest.json",
)
SOURCE_INFO = (
    "source-info.json",
    "threat-intel-source-info.json",
    "bridges-source-info.json",
    "geoip-source-info.json",
    "fingerprint-source-info.json",
)
DAY = 86_400
RENEW_AGE = 21 * DAY
RENEW_REMAINING = 7 * DAY
MAX_METADATA = 1_048_576
MAX_FINGERPRINTS = 4_194_304


def read_json(path):
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must be an object")
    return value


def normalized(document):
    return {
        key: value for key, value in document.items()
        if key not in {"generated_at", "generated_at_unix", "expires_at_unix", "sequence"}
    }


def generated_at(document):
    if "generated_at_unix" in document:
        return int(document["generated_at_unix"])
    return int(datetime.datetime.fromisoformat(document["generated_at"].replace("Z", "+00:00")).timestamp())


def verified_fingerprint(directory, manifest):
    artifact = manifest["artifact"]
    if artifact["file"] != "fingerprints.json":
        raise ValueError("Unexpected fingerprint artifact")
    payload = (directory / "fingerprints.json").read_bytes()
    if len(payload) != artifact["size"] or len(payload) > MAX_FINGERPRINTS:
        raise ValueError("Fingerprint size mismatch")
    if hashlib.sha256(payload).hexdigest() != artifact["sha256"]:
        raise ValueError("Fingerprint digest mismatch")
    document = json.loads(payload)
    return {key: value for key, value in document.items() if key != "generated_at"}


def publication_reason(candidate, published, now):
    for name in MANIFESTS:
        incoming = read_json(candidate / name)
        previous = read_json(published / name)
        age = now - generated_at(previous)
        if age < -300 or age >= RENEW_AGE:
            return f"{name} needs freshness renewal"
        if "expires_at_unix" in previous and int(previous["expires_at_unix"]) - now <= RENEW_REMAINING:
            return f"{name} is approaching expiry"
        left, right = normalized(incoming), normalized(previous)
        if name == "fingerprint-manifest.json":
            if verified_fingerprint(candidate, incoming) != verified_fingerprint(published, previous):
                return "Fingerprint tables or provenance changed"
            # The signed artifact differs only by its build timestamp, which was checked above.
            left = {**left, "artifact": {**left["artifact"], "sha256": "", "size": 0}}
            right = {**right, "artifact": {**right["artifact"], "sha256": "", "size": 0}}
        if left != right:
            return f"{name} data or contract changed"
    for name in SOURCE_INFO:
        if normalized(read_json(candidate / name)) != normalized(read_json(published / name)):
            return f"{name} provenance changed"
    return None


def download(base, name, destination, limit):
    request = urllib.request.Request(f"{base.rstrip('/')}/{name}?check={time.time_ns()}")
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError("Published feed redirected outside HTTPS")
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"{name} exceeds its download limit")
    destination.write_bytes(payload)


def verify_signature(manifest, public_key):
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key),
         "-signature", str(manifest) + ".sig", str(manifest)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    if result.returncode:
        raise ValueError(f"{manifest.name} has no valid publication signature")


def main():
    candidate = Path(os.environ["CANDIDATE_DIR"])
    base = os.environ["PUBLISHED_BASE_URL"]
    if not base.startswith("https://"):
        raise ValueError("Pages comparison requires HTTPS")
    public_key = Path(__file__).resolve().parent / "manifest.public.pem"
    try:
        with tempfile.TemporaryDirectory(prefix="foxhole-feed-compare-") as temporary:
            published = Path(temporary)
            for name in MANIFESTS:
                download(base, name, published / name, MAX_METADATA)
                download(base, name + ".sig", published / (name + ".sig"), 1_024)
                verify_signature(published / name, public_key)
            download(base, "fingerprints.json", published / "fingerprints.json", MAX_FINGERPRINTS)
            for name in SOURCE_INFO:
                download(base, name, published / name, MAX_METADATA)
            reason = publication_reason(candidate, published, int(time.time()))
    except (OSError, ValueError, KeyError, TypeError):
        reason = "The current publication could not be verified; republish the verified candidate"
    print(f"publish={'true' if reason else 'false'}")
    print(reason or "Data and provenance are unchanged; published signatures remain fresh", file=sys.stderr)


if __name__ == "__main__":
    main()
