#!/usr/bin/env python3
"""Build canonical suffix-only tagged input from explicitly pinned source files."""
import argparse
import hashlib
import json
import io
from pathlib import Path
import re
from urllib.parse import urlsplit

CATEGORIES = ("malicious", "telemetry", "trackers", "ads")
DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")
ADB = re.compile(r"(@@)?\|\|([A-Za-z0-9.-]+)\^(?:\$important)?")
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 5_000_000


def strict_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def domain(raw):
    value = raw.strip().lower().rstrip(".")
    if len(value) > 253 or not DOMAIN.fullmatch(value) or any(len(label) > 63 for label in value.split(".")):
        raise ValueError("invalid suffix domain")
    return value


def beneath(root, relative):
    path = Path(relative)
    if path.is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")) or "\\" in relative:
        raise ValueError("input path is not portable relative path")
    candidate = root / path
    if candidate.is_symlink() or not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError("input leaves source root")
    return candidate


def categories(values):
    if not isinstance(values, list) or not values or values != [name for name in CATEGORIES if name in values]:
        raise ValueError("categories must be unique canonical names")
    return values


def is_allowed(value, suffixes):
    labels = value.split(".")
    return any(".".join(labels[index:]) in suffixes for index in range(len(labels)))


def convert_source(data, format_name):
    block, allow = set(), set()
    skipped = 0
    for line in data.decode("utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith(("#", "!")) or value.startswith("["):
            continue
        match = ADB.fullmatch(value) if format_name == "adblock-suffix" else None
        try:
            if match:
                destination = domain(match.group(2))
                (allow if match.group(1) else block).add(destination)
            elif format_name == "domain-suffix":
                block.add(domain(value))
            else:
                skipped += 1
        except ValueError:
            skipped += 1
    return block, allow, skipped


def build_tagged_parts(spec, source_root):
    if set(spec) != {"schema", "tiers", "sources", "allow_suffixes"} or (type(spec["schema"]) is not int or spec["schema"] != 1):
        raise ValueError("unsupported source specification")
    tiers = spec["tiers"]
    if set(tiers) != {"trackers", "malicious"} or tiers["trackers"] not in ("normal", "pro") or tiers["malicious"] not in ("medium", "full"):
        raise ValueError("unsupported tiers")
    if not 1 <= len(spec["sources"]) <= 16:
        raise ValueError("source cardinality")
    descriptors, rules, statistics = [], {}, []
    ids = set()
    for source in spec["sources"]:
        if set(source) != {"id", "repo", "commit", "license", "inputs", "categories", "format"}:
            raise ValueError("unknown source specification fields")
        if source["id"] in ids:
            raise ValueError("duplicate source id")
        ids.add(source["id"])
        selected = categories(source["categories"])
        if source["format"] not in ("adblock-suffix", "domain-suffix") or not 1 <= len(source["inputs"]) <= 16:
            raise ValueError("source format/input cardinality")
        for key in ("id", "repo", "commit", "license"):
            if not isinstance(source[key], str) or not source[key] or not source[key].isascii():
                raise ValueError("source metadata must be bounded ASCII strings")
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", source["id"]) or not re.fullmatch(r"[0-9a-f]{40}", source["commit"]):
            raise ValueError("source identity/commit")
        repo = urlsplit(source["repo"])
        if (repo.scheme != "https" or not repo.hostname or repo.username is not None or repo.fragment
                or len(source["repo"]) > 512 or len(source["license"]) > 128):
            raise ValueError("source repo/license")
        if len({row["path"] for row in source["inputs"]}) != len(source["inputs"]):
            raise ValueError("duplicate source input")
        emitted, exceptions, skipped = set(), set(), 0
        for input_file in source["inputs"]:
            if set(input_file) != {"path", "sha256"}:
                raise ValueError("input specification fields")
            path = beneath(source_root / source["id"], input_file["path"])
            if not path.is_file() or not 1 <= path.stat().st_size <= MAX_INPUT_BYTES:
                raise ValueError("source file bounds")
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != input_file["sha256"]:
                raise ValueError("source digest mismatch")
            current, allowed, invalid = convert_source(data, source["format"])
            emitted.update(current)
            exceptions.update(allowed)
            skipped += invalid
        emitted = {entry for entry in emitted if not is_allowed(entry, exceptions)}
        if not emitted:
            raise ValueError("source contains no supported suffix rules")
        descriptor = {key: source[key] for key in ("id", "repo", "commit", "license", "inputs", "categories")}
        descriptor["inputs"] = sorted(descriptor["inputs"], key=lambda row: row["path"])
        descriptors.append(descriptor)
        for value in emitted:
            flags = sum(1 << CATEGORIES.index(name) for name in selected)
            rules[value] = rules.get(value, 0) | flags
        if len(rules) > MAX_ENTRIES:
            raise ValueError("entry limit")
        statistics.append({"source": source["id"], "emitted": len(emitted), "skipped": skipped})
    global_allow = sorted({domain(value) for value in spec["allow_suffixes"]})
    global_allow_set = set(global_allow)
    rules = {value: selected for value, selected in rules.items() if not is_allowed(value, global_allow_set)}
    present = [name for index, name in enumerate(CATEGORIES) if any(flags & (1 << index) for flags in rules.values())]
    declared = {category for source in descriptors for category in source["categories"]}
    if not present or set(present) != declared:
        raise ValueError("required category has no emitted rules")
    tagged = {
        "schema": 1, "categories": present, "tiers": tiers,
        "sources": sorted(descriptors, key=lambda row: row["id"]),
        "allow_suffixes": global_allow,
    }
    return tagged, rules, statistics


def write_tagged(stream, tagged, rules):
    encoded = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    stream.write(b'{"allow_suffixes":' + encoded(tagged["allow_suffixes"]) + b',"block":[')
    counts = {name: 0 for name in CATEGORIES}
    first = True
    for domain_name in sorted(rules):
        flags = rules[domain_name]
        names = [name for index, name in enumerate(CATEGORIES) if flags & (1 << index)]
        for name in names:
            counts[name] += 1
        if not first:
            stream.write(b',')
        stream.write(encoded({"domain": domain_name, "categories": names}))
        first = False
    stream.write(b']')
    for key in ("categories", "schema", "sources", "tiers"):
        stream.write(b',' + encoded(key) + b':' + encoded(tagged[key]))
    stream.write(b'}\n')
    return counts


def build_tagged(spec, source_root):
    tagged, rules, statistics = build_tagged_parts(spec, source_root)
    output = io.BytesIO()
    write_tagged(output, tagged, rules)
    return output.getvalue(), statistics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-spec", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--tagged-output", type=Path, required=True)
    parser.add_argument("--stats-output", type=Path, required=True)
    args = parser.parse_args()
    data, stats = build_tagged(strict_json(args.source_spec.read_text()), args.source_root)
    args.tagged_output.write_bytes(data)
    args.stats_output.write_bytes(canonical(stats))


if __name__ == "__main__":
    main()
