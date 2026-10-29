#!/usr/bin/env python3
"""Create canonical schema3 from verified tagged input and compiler output."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import subprocess

module = importlib.util.spec_from_file_location("converter", Path(__file__).with_name("build-dns-categories.py"))
converter = importlib.util.module_from_spec(module)
module.loader.exec_module(converter)


def checked_u64(value, label, positive=False):
    if type(value) is not int or not (1 if positive else 0) <= value <= 2**64 - 1:
        raise ValueError(f"invalid {label} u64")
    return value


def manifest(tagged_bytes, artifact, key_hash, sequence, generated, expires):
    tagged = converter.strict_json(tagged_bytes.decode())
    if converter.canonical(tagged) != tagged_bytes:
        raise ValueError("noncanonical tagged input")
    counts = {category: sum(category in row["categories"] for row in tagged["block"])
              for category in converter.CATEGORIES}
    return manifest_claims(tagged, hashlib.sha256(tagged_bytes).hexdigest(), len(tagged["block"]),
                           counts, artifact, key_hash, sequence, generated, expires)


def manifest_claims(tagged, tagged_hash, expected_blocks, counts, artifact, key_hash, sequence, generated, expires):
    if not re.fullmatch(r"[0-9a-f]{64}", key_hash):
        raise ValueError("invalid public key digest")
    checked_u64(sequence, "sequence", positive=True)
    checked_u64(generated, "generated", positive=True)
    checked_u64(expires, "expires", positive=True)
    if not 0 < expires - generated <= 31 * 86400:
        raise ValueError("invalid validity window")
    if not 80 <= len(artifact) <= 64 * 1024 * 1024 or artifact[:8] != b"FHDNS1\0\0":
        raise ValueError("invalid compiler artifact")
    block_count, allow_count, block_size, allow_size = struct.unpack(">QQQQ", artifact[8:40])
    if artifact[40:72].hex() != tagged_hash or artifact[72:80] != bytes(8):
        raise ValueError("compiler source/reserved header mismatch")
    if 80 + block_size + allow_size != len(artifact):
        raise ValueError("compiler payload length mismatch")
    if block_count != expected_blocks or allow_count != len(tagged["allow_suffixes"]):
        raise ValueError("compiler header counts mismatch")
    tiers = tagged["tiers"]
    return {
        "schema": 3, "name": f"foxhole-dns-categories-{tiers['trackers']}-{tiers['malicious']}",
        "format": "foxhole-dns-fst-v1", "sequence": sequence,
        "generated_at_unix": generated, "expires_at_unix": expires,
        "key_sha256": key_hash, "categories": tagged["categories"], "tiers": tiers,
        "tagged_input_sha256": tagged_hash, "sources": tagged["sources"],
        "artifact": {"file": "dns-categories.fhds", "size": len(artifact),
                     "sha256": hashlib.sha256(artifact).hexdigest(),
                     "block_entries": block_count, "allow_entries": allow_count,
                     "category_entries": counts},
        "compatibility": {"core_schema": 1, "category_schema": 1},
    }


def build_variant(spec_path, source_root, compiler, output, key_hash, sequence, generated, expires):
    spec = converter.strict_json(spec_path.read_text())
    tagged, rules, stats = converter.build_tagged_parts(spec, source_root)
    output.mkdir(parents=True, exist_ok=True)
    tagged_path = output / "tagged-input.json"
    artifact_path = output / "dns-categories.fhds"
    with tagged_path.open("wb") as stream:
        counts = converter.write_tagged(stream, tagged, rules)
    tagged_hash = hashlib.sha256()
    with tagged_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            tagged_hash.update(chunk)
    expected_blocks = len(rules)
    del rules
    subprocess.run([str(compiler), "--tagged-input", str(tagged_path), "--output", str(artifact_path)], check=True)
    artifact = artifact_path.read_bytes()
    value = manifest_claims(tagged, tagged_hash.hexdigest(), expected_blocks, counts,
                            artifact, key_hash, sequence, generated, expires)
    manifest_bytes = converter.canonical(value)
    (output / "manifest.json").write_bytes(manifest_bytes)
    (output / "dns-categories.fhds.sha256").write_text(value["artifact"]["sha256"] + "  dns-categories.fhds\n")
    (output / "conversion-stats.json").write_bytes(converter.canonical(stats))
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-spec", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key-sha256", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--generated", type=int, required=True)
    parser.add_argument("--expires", type=int, required=True)
    args = parser.parse_args()
    build_variant(args.source_spec, args.source_root, args.compiler, args.output, args.key_sha256,
                  args.sequence, args.generated, args.expires)


if __name__ == "__main__":
    main()
