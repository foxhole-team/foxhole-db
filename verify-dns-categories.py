#!/usr/bin/env python3
"""Verify signed canonical categorized delivery without network or private keys."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import subprocess
import time
from urllib.parse import urlsplit

module = importlib.util.spec_from_file_location("producer", Path(__file__).with_name("dns-categories-manifest.py"))
producer = importlib.util.module_from_spec(module)
module.loader.exec_module(producer)
converter = producer.converter


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected.split()):
        raise ValueError("unknown or missing categorized field")


def hexadecimal(value, length):
    if not isinstance(value, str) or re.fullmatch(f"[0-9a-f]{{{length}}}", value) is None:
        raise ValueError("invalid categorized digest")


def validate(raw, artifact, key_hash, now):
    value = converter.strict_json(raw.decode("ascii"))
    if converter.canonical(value) != raw:
        raise ValueError("noncanonical categorized manifest")
    fields(value, "schema name format sequence generated_at_unix expires_at_unix key_sha256 categories tiers tagged_input_sha256 sources artifact compatibility")
    if type(value["schema"]) is not int or value["schema"] != 3 or value["format"] != "foxhole-dns-fst-v1":
        raise ValueError("unsupported categorized schema/format")
    fields(value["tiers"], "trackers malicious")
    tiers = value["tiers"]
    if tiers["trackers"] not in ("normal", "pro") or tiers["malicious"] not in ("medium", "full"):
        raise ValueError("unknown tier")
    if value["name"] != f"foxhole-dns-categories-{tiers['trackers']}-{tiers['malicious']}":
        raise ValueError("tier/name mismatch")
    for key in ("sequence", "generated_at_unix", "expires_at_unix"):
        producer.checked_u64(value[key], key, positive=True)
    if not 0 < value["expires_at_unix"] - value["generated_at_unix"] <= 31 * 86400:
        raise ValueError("invalid validity")
    if value["generated_at_unix"] > min(2**64 - 1, now + 600) or now >= value["expires_at_unix"]:
        raise ValueError("expired or future categorized manifest")
    hexadecimal(value["key_sha256"], 64)
    if value["key_sha256"] != key_hash:
        raise ValueError("public key identity mismatch")
    hexadecimal(value["tagged_input_sha256"], 64)
    converter.categories(value["categories"])
    sources = value["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 16:
        raise ValueError("source cardinality")
    ids = []
    contributing = set()
    for source in sources:
        fields(source, "id repo commit license inputs categories")
        if not isinstance(source["id"], str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", source["id"]) is None:
            raise ValueError("source id")
        ids.append(source["id"])
        hexadecimal(source["commit"], 40)
        for key, limit in (("repo", 512), ("license", 128)):
            text = source[key]
            if not isinstance(text, str) or not 1 <= len(text) <= limit or any(ord(c) < 32 or ord(c) > 126 for c in text):
                raise ValueError("source ASCII metadata")
        repo = urlsplit(source["repo"])
        if repo.scheme != "https" or not repo.hostname or repo.username is not None or repo.fragment:
            raise ValueError("source repository")
        converter.categories(source["categories"])
        contributing.update(source["categories"])
        inputs = source["inputs"]
        if not isinstance(inputs, list) or not 1 <= len(inputs) <= 16:
            raise ValueError("input cardinality")
        paths = []
        for row in inputs:
            fields(row, "path sha256")
            text = row["path"]
            if not isinstance(text, str) or not 1 <= len(text) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in text):
                raise ValueError("input ASCII path")
            if text.startswith("/") or "\\" in text or any(part in ("", ".", "..") for part in text.split("/")):
                raise ValueError("input portable path")
            paths.append(text)
            hexadecimal(row["sha256"], 64)
        if paths != sorted(set(paths)):
            raise ValueError("input path order/duplicates")
    if ids != sorted(set(ids)) or contributing != set(value["categories"]):
        raise ValueError("source order/availability")
    claimed = value["artifact"]
    fields(claimed, "file size sha256 block_entries allow_entries category_entries")
    if claimed["file"] != "dns-categories.fhds" or not 80 <= producer.checked_u64(claimed["size"], "size") <= 67108864:
        raise ValueError("artifact identity/size")
    for key in ("block_entries", "allow_entries"):
        producer.checked_u64(claimed[key], key)
    if not 1 <= claimed["block_entries"] <= 5000000 or claimed["allow_entries"] > 5000000:
        raise ValueError("entry count")
    fields(claimed["category_entries"], "malicious telemetry trackers ads")
    for name, count in claimed["category_entries"].items():
        producer.checked_u64(count, name)
        if count > claimed["block_entries"] or (count > 0) != (name in value["categories"]):
            raise ValueError("category availability/count")
    hexadecimal(claimed["sha256"], 64)
    if len(artifact) != claimed["size"] or hashlib.sha256(artifact).hexdigest() != claimed["sha256"]:
        raise ValueError("artifact size/hash")
    if artifact[:8] != b"FHDNS1\0\0" or artifact[72:80] != bytes(8):
        raise ValueError("artifact header")
    blocks, allows, block_size, allow_size = struct.unpack(">QQQQ", artifact[8:40])
    if (blocks, allows) != (claimed["block_entries"], claimed["allow_entries"]) or 80 + block_size + allow_size != len(artifact):
        raise ValueError("artifact header counts")
    if artifact[40:72].hex() != value["tagged_input_sha256"]:
        raise ValueError("tagged source identity")
    fields(value["compatibility"], "core_schema category_schema")
    if any(type(x) is not int or x != 1 for x in value["compatibility"].values()):
        raise ValueError("category compatibility")
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--unsigned", action="store_true")
    args = parser.parse_args()
    manifest = args.directory / "manifest.json"
    artifact = args.directory / "dns-categories.fhds"
    if not 1 <= manifest.stat().st_size <= 65536 or not 80 <= artifact.stat().st_size <= 67108864:
        raise ValueError("file bounds")
    if not args.unsigned:
        subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(args.public_key),
                        "-signature", str(manifest)+".sig", str(manifest)], check=True)
    der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(args.public_key), "-outform", "DER"])
    value = validate(manifest.read_bytes(), artifact.read_bytes(), hashlib.sha256(der).hexdigest(), int(time.time()))
    if args.directory.name != f"{value['tiers']['trackers']}-{value['tiers']['malicious']}":
        raise ValueError("manifest directory variant mismatch")
    print("verified categorized manifest/hash/header", value["name"])


if __name__ == "__main__":
    main()
