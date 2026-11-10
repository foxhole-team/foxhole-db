#!/usr/bin/env python3
"""Create an automatically validated immutable DNS input snapshot without Git writes."""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pinned_fetch", ROOT / "fetch-dns-category-sources.py")
pinned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pinned)
converter = pinned.converter
MAX_INPUT_BYTES = converter.MAX_INPUT_BYTES
MAX_METADATA_BYTES = 1024 * 1024
VARIANTS = ("normal-full", "normal-medium", "pro-full", "pro-medium")


def fetch_bytes(url, limit):
    with tempfile.TemporaryDirectory(prefix="foxhole-source-download-") as temporary:
        output = Path(temporary) / "body"
        subprocess.run([
            "curl", "--fail", "--silent", "--show-error", "--proto", "=https",
            "--connect-timeout", "10", "--max-time", "30", "--retry", "2",
            "--retry-max-time", "90", "--max-filesize", str(limit),
            "--user-agent", "FoxHole-DNS-source-snapshot", "--output", str(output), url,
        ], check=True, timeout=95)
        if not 0 < output.stat().st_size <= limit:
            raise ValueError("download bounds")
        return output.read_bytes()


def read_remote(fetch, url, limit):
    raw = fetch(url, limit)
    if not isinstance(raw, bytes) or not 0 < len(raw) <= limit:
        raise ValueError("download bounds")
    return raw


def canonical_file(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(converter.canonical(document))


def select_policy(spec_directory):
    paths = sorted(spec_directory.glob("*.json"))
    if [p.stem for p in paths] != list(VARIANTS):
        raise ValueError("exactly four source variants are required")
    specifications, sources, policy_hashes = {}, {}, {}
    for path in paths:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_METADATA_BYTES:
            raise ValueError("source policy bounds")
        raw = path.read_bytes()
        value = converter.strict_json(raw)
        if (not isinstance(value, dict) or set(value) != {"schema", "tiers", "sources", "allow_suffixes"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or not isinstance(value["sources"], list) or not 1 <= len(value["sources"]) <= 16):
            raise ValueError("source policy schema")
        seen = set()
        for source in value["sources"]:
            if (not isinstance(source, dict)
                    or set(source) != {"id", "repo", "commit", "license", "inputs", "categories", "format"}
                    or source["repo"] not in pinned.REPOSITORIES
                    or not isinstance(source["id"], str)
                    or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", source["id"]) is None
                    or source["id"] in seen
                    or not isinstance(source["inputs"], list) or not 1 <= len(source["inputs"]) <= 16):
                raise ValueError("unsupported source policy")
            seen.add(source["id"])
            for row in source["inputs"]:
                if (not isinstance(row, dict) or set(row) != {"path", "sha256"}
                        or not isinstance(row["path"], str)):
                    raise ValueError("source input policy")
                converter.beneath(Path("/source-policy"), row["path"])
            if source["id"] in sources and sources[source["id"]] != source:
                raise ValueError("conflicting source policy")
            sources[source["id"]] = source
        specifications[path.name] = value
        policy_hashes[path.name] = hashlib.sha256(raw).hexdigest()
    return specifications, sources, policy_hashes


def refresh_sources(spec_directory, output, fetch=fetch_bytes, now=None):
    output, spec_directory = Path(output), Path(spec_directory)
    if output.exists() or output.is_symlink():
        raise FileExistsError("snapshot destination already exists")
    observed = int(time.time()) if now is None else now
    if type(observed) is not int or observed <= 0:
        raise ValueError("invalid observation time")
    specifications, sources, policy_hashes = select_policy(spec_directory)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".foxhole-source-snapshot-", dir=output.parent))
    try:
        pins, metadata = {}, []
        for repo in sorted({source["repo"] for source in sources.values()}):
            repository = repo.removeprefix("https://github.com/")
            api = f"https://api.github.com/repos/{repository}/commits"
            head_raw = read_remote(fetch, api + "?per_page=1", MAX_METADATA_BYTES)
            rows = converter.strict_json(head_raw)
            if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
                raise ValueError("invalid official HEAD response")
            head = rows[0]
            sha = head.get("sha")
            if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
                raise ValueError("invalid official commit identity")
            exact_url = api + "/" + sha
            exact_raw = read_remote(fetch, exact_url, MAX_METADATA_BYTES)
            exact = converter.strict_json(exact_raw)
            if (not isinstance(exact, dict) or exact.get("sha") != sha
                    or exact.get("url") != exact_url or head.get("url") != exact_url
                    or exact.get("html_url") != repo + "/commit/" + sha):
                raise ValueError("official commit identity mismatch")
            try:
                date = exact["commit"]["committer"]["date"]
                if date != head["commit"]["committer"]["date"]:
                    raise ValueError("official commit timestamp mismatch")
                stamp = int(datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp())
            except (KeyError, TypeError) as error:
                raise ValueError("invalid official commit timestamp") from error
            pins[repo] = {"repo": repo, "commit": sha, "committed_at_unix": stamp, "api_url": exact_url}
            for name, raw in [("head", head_raw), ("commit", exact_raw)]:
                target = temporary / "upstream" / repository / (name + ".json")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                metadata.append({"file": str(target.relative_to(temporary)), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
        review = {"schema": 1, "reviewed_at_unix": observed, "sources": [pins[repo] for repo in sorted(pins)]}
        canonical_file(temporary / "dns-category-source-pins.json", review)
        for name, value in specifications.items():
            for source in value["sources"]:
                source["commit"] = pins[source["repo"]]["commit"]
            converter.check_source_age(value, temporary / "dns-category-source-pins.json", now=observed)
        refreshed, audit_sources = {}, []
        for source_id, source in sorted(sources.items()):
            commit = pins[source["repo"]]["commit"]
            block, allow, unsupported, inputs = set(), set(), 0, []
            for row in source["inputs"]:
                relative = row["path"]
                repository = source["repo"].removeprefix("https://github.com/")
                url = f"https://raw.githubusercontent.com/{repository}/{commit}/{quote(relative, safe='/')}"
                raw = read_remote(fetch, url, MAX_INPUT_BYTES)
                digest = hashlib.sha256(raw).hexdigest()
                target = converter.beneath(temporary / "sources" / source_id, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                emitted, exceptions, skipped = converter.convert_source(raw, source["format"])
                block.update(emitted); allow.update(exceptions); unsupported += skipped
                if len(block) > converter.MAX_ENTRIES or len(allow) > converter.MAX_ENTRIES:
                    raise ValueError("source entry limit")
                refreshed[source_id, relative] = digest
                inputs.append({"path": relative, "url": url, "bytes": len(raw), "sha256": digest})
            supported = {entry for entry in block if not converter.is_allowed(entry, allow)}
            audit_sources.append({"id": source_id, "repo": source["repo"], "commit": commit,
                                  "supported_suffixes": len(supported), "exceptions": len(allow),
                                  "unsupported_lines": unsupported, "inputs": inputs})
        for name, value in specifications.items():
            for source in value["sources"]:
                for row in source["inputs"]:
                    row["sha256"] = refreshed[source["id"], row["path"]]
            converter.check_source_age(value, temporary / "dns-category-source-pins.json", now=now)
            converter.build_tagged_parts(value, temporary / "sources")
            canonical_file(temporary / "specs" / name, value)
        canonical_file(temporary / "audit.json", {
            "schema": 1, "validation": "automatic_validation", "human_review_claimed": False,
            "observed_at_unix": observed, "source_policy_sha256": policy_hashes,
            "metadata": metadata, "sources": audit_sources,
        })
        temporary.rename(output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    refresh_sources(args.spec_dir, args.output)
    print("Validated automatic immutable DNS source snapshot:", args.output)


if __name__ == "__main__":
    main()
