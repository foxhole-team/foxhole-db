"""Strict owner-signed native-SDK compiler admission, separate from the legacy full-lab family."""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unicodedata

META_MAX = 1048576
ARCHIVE_MAX = 512 * META_MAX
COMPILER_PATH = "payload/bin/linux-x86_64/foxcore-dns-compile"
COMPILER_TARGET = "x86_64-unknown-linux-gnu"
EQUIVALENCE_PATH = "metadata/GNU-SOURCE-EQUIVALENCE.json"
LEGACY_NATIVE_SDK_SHA = "01803e0f63841e1514adae978be0bfcafa20a1d69a2620ce74f96ea2e4a902ae"
LEGACY_GNU_RECEIPT_SHA = "f9ed67055eba4e0d8121d3de0efa6feef4c7ad3805c0ea0080677752cd169a82"
# Exact actual producer-receipt authorities are independent of optional SDK labels.
# New producers need review; deleting origin metadata must never create a legacy identity.
GNU_RECEIPT_AUTHORITIES = {
    "f9ed67055eba4e0d8121d3de0efa6feef4c7ad3805c0ea0080677752cd169a82": {
        "commit": "fc2134dc15b32087516672935e64ae7b8b0d5472", "tree": "d3e79095b3a955420ac2d89cb0f1437a6a147713",
        "sourceInputsSha256": "528b727248ca98673df8a99f6541b6a9edbdc14588ab38141ba1cdc17847d74c",
        "version": "1.0.3", "sha256": "dd830749c246cb6d8f2c8a5d6368cfb7e18f1b562c5ec29ae391c2e9a1520414", "bytes": 513448},
    "b6fcf2f6fc6c05681dfec0100325040c63676af80d80e4a8974e428ac2a776b7": {
        "commit": "44e2d1179559448824016cd5bf6b97a7a82832f2", "tree": "97cb5fd235a3566ce0cdc3060a94d6f37678cab7",
        "sourceInputsSha256": "69f8fb78435fea010970e1e046b201205229c68d0724b8aa479b803451410272",
        "version": "1.0.4", "sha256": "03d50e775ff6e1ce1e706a8df147d6eefb4bd0ca83f34cee847892e02c73ca21", "bytes": 513448},
}
ASSETS = {"sdk", "source", "sourceSignature", "checksums", "checksumsSignature"}


def need(value, message):
    if not value:
        raise ValueError(message)


def strict_json(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def hex_value(value, length):
    return isinstance(value, str) and value != "0" * length and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def safe_file(path, maximum=META_MAX):
    path = Path(path)
    info, parent = path.lstat(), path.parent.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_ISDIR(parent.st_mode)
         and not (info.st_mode | parent.st_mode) & 0o022 and 0 < info.st_size <= maximum,
         "bounded regular nlink1 file and safe parent required: " + path.name)
    return info


def file_hash(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unchanged_file(path, before):
    def fence(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid, value.st_gid,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    return fence(before) == fence(Path(path).lstat())


def validate_pin(pin):
    keys = {"schema", "family", "version", "releaseTag", "sourceCommit", "sourceTree", "producerCommit",
            "producerTree", "sourceInputsSha256", "compiledInputsSha256", "compiledInputCount",
            "nativeManifestSha256", "payloadManifestSha256", "policy", "assets", "compiler"}
    need(isinstance(pin, dict) and set(pin) == keys and type(pin["schema"]) is int
         and pin["schema"] == 2 and pin["family"] == "native-sdk", "invalid native compiler pin schema")
    need(isinstance(pin["version"], str) and re.fullmatch(r"[0-9]+[.][0-9]+[.][0-9]+", pin["version"])
         and pin["releaseTag"] == "v" + pin["version"], "unbound native release/version")
    for key in ("sourceCommit", "sourceTree", "producerCommit", "producerTree"):
        need(hex_value(pin[key], 40), "unbound native source/producer pin")
    for key in ("sourceInputsSha256", "compiledInputsSha256", "nativeManifestSha256", "payloadManifestSha256"):
        need(hex_value(pin[key], 64), "unbound native metadata digest")
    need(type(pin["compiledInputCount"]) is int and 1 <= pin["compiledInputCount"] <= 10000,
         "unbound compiled input count")
    need(isinstance(pin["policy"], dict) and set(pin["policy"]) == {"keysSha256", "fingerprintsSha256"}
         and all(hex_value(value, 64) for value in pin["policy"].values()), "unbound owner policy")
    need(isinstance(pin["assets"], dict) and set(pin["assets"]) == ASSETS, "exact native release asset set required")
    names = []
    for role, row in pin["assets"].items():
        need(isinstance(row, dict) and set(row) == {"name", "sha256", "bytes"}, "invalid native asset fields")
        need(isinstance(row["name"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", row["name"])
             and row["name"] not in (".", "..") and hex_value(row["sha256"], 64), "unbound native asset name/hash")
        bound = ARCHIVE_MAX if role in ("sdk", "source") else META_MAX
        need(type(row["bytes"]) is int and 0 < row["bytes"] <= bound, "unbound native asset size")
        names.append(row["name"].casefold())
    need(len(set(names)) == 5, "duplicate/casefold-colliding native assets")
    need(pin["assets"]["checksums"]["name"] == "SHA256SUMS"
         and pin["assets"]["checksumsSignature"]["name"] == "SHA256SUMS.asc", "native checksum roles differ")
    compiler = pin["compiler"]
    compiler_keys = {"path", "sha256", "bytes", "target", "producerReceiptSha256"}
    need(isinstance(compiler, dict) and set(compiler) in (compiler_keys, compiler_keys | {"origin"}),
         "invalid compiler role fields")
    need(compiler["path"] == COMPILER_PATH and compiler["target"] == COMPILER_TARGET
         and hex_value(compiler["sha256"], 64) and hex_value(compiler["producerReceiptSha256"], 64)
         and type(compiler["bytes"]) is int and 64 <= compiler["bytes"] <= 16 * META_MAX,
         "unbound or unsupported native GNU compiler role")
    authority = GNU_RECEIPT_AUTHORITIES.get(compiler["producerReceiptSha256"])
    need(authority is not None and compiler["sha256"] == authority["sha256"] and compiler["bytes"] == authority["bytes"]
         and pin["version"] == authority["version"], "unreviewed or mismatched actual GNU producer receipt")
    if "origin" not in compiler:
        need(pin["assets"]["sdk"]["sha256"] == LEGACY_NATIVE_SDK_SHA
             and compiler["producerReceiptSha256"] == LEGACY_GNU_RECEIPT_SHA
             and pin["producerCommit"] == authority["commit"] and pin["producerTree"] == authority["tree"]
             and pin["sourceInputsSha256"] == authority["sourceInputsSha256"],
             "actual GNU producer differs; explicit retained origin cannot be stripped")
    if "origin" in compiler:
        origin = compiler["origin"]
        need(isinstance(origin, dict) and set(origin) == {"mode", "producerCommit", "producerTree", "sourceInputsSha256",
             "consumerCommit", "consumerTree", "consumerSourceInputsSha256", "equivalencePath", "equivalenceSha256",
             "rootAcceptanceSha256"} and origin["mode"] == "retained-source-equivalence-v1",
             "invalid retained GNU origin fields")
        for key in ("producerCommit", "producerTree", "consumerCommit", "consumerTree"):
            need(hex_value(origin[key], 40), "unbound retained GNU source identity")
        for key in ("sourceInputsSha256", "consumerSourceInputsSha256", "equivalenceSha256", "rootAcceptanceSha256"):
            need(hex_value(origin[key], 64), "unbound retained GNU source proof")
        need(origin["producerCommit"] != pin["producerCommit"] and origin["consumerCommit"] == pin["producerCommit"]
             and origin["consumerTree"] == pin["producerTree"]
             and origin["consumerSourceInputsSha256"] == pin["sourceInputsSha256"]
             and origin["equivalencePath"] == EQUIVALENCE_PATH, "retained GNU consumer/origin differs")
        need(origin["producerCommit"] == authority["commit"] and origin["producerTree"] == authority["tree"]
             and origin["sourceInputsSha256"] == authority["sourceInputsSha256"], "actual retained GNU producer receipt identity differs")
    return pin


def portable(name):
    need(isinstance(name, str) and name and "\x00" not in name and "\\" not in name
         and unicodedata.normalize("NFC", name) == name and not any(ord(char) < 32 for char in name),
         "nonportable archive path")
    path = PurePosixPath(name)
    need(not path.is_absolute() and str(path) == name and all(part not in ("", ".", "..") for part in name.split("/")),
         "archive path traversal/alias")
    need(not any(part.casefold() in (".git", ".local-secrets", "agents.md") for part in path.parts),
         "private/operational archive path refused")


def tar_index(path):
    safe_file(path, ARCHIVE_MAX)
    result, folded, total = {}, set(), 0
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            portable(member.name)
            need(member.isfile() and member.name not in result and member.name.casefold() not in folded,
                 "nonregular/duplicate/casefold archive member")
            need(0 <= member.size <= 128 * META_MAX and member.mode & 0o7777 in (0o644, 0o755),
                 "archive member size/mode refused")
            total += member.size
            need(total <= 1024 * META_MAX and len(result) < 10000, "archive expansion/count bound")
            result[member.name] = member
            folded.add(member.name.casefold())
    for name in result:
        parts = name.split("/")
        need(not any("/".join(parts[:index]).casefold() in folded for index in range(1, len(parts))),
             "archive file/directory prefix collision")
    return result


def member_bytes(path, index, name, maximum=META_MAX):
    need(name in index and 0 < index[name].size <= maximum, "missing/bounded native role: " + name)
    with tarfile.open(path, "r:*") as archive:
        with archive.extractfile(index[name]) as stream:
            raw = stream.read(maximum + 1)
    need(len(raw) == index[name].size and len(raw) <= maximum, "native member length differs")
    return raw


def checked_assets(pin, directory):
    directory = Path(directory)
    need(directory.is_dir() and not directory.is_symlink() and not directory.stat().st_mode & 0o022,
         "safe actual asset directory required")
    paths = {}
    for role, row in pin["assets"].items():
        path = directory / row["name"]
        info = safe_file(path, ARCHIVE_MAX if role in ("sdk", "source") else META_MAX)
        need(info.st_size == row["bytes"] and file_hash(path) == row["sha256"], "pinned native asset bytes differ: " + role)
        paths[role] = path
    return paths


def producer_tree(path, index):
    """Reproduce the source snapshot's Git tree identity without running Git."""
    root = {}
    with tarfile.open(path, "r:*") as archive:
        for name, row in index.items():
            node = root
            parts = name.split("/")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
                need(isinstance(node, dict), "source file/directory collision")
            hashed = hashlib.sha1(b"blob " + str(row.size).encode() + b"\0")
            with archive.extractfile(row) as stream:
                for chunk in iter(lambda: stream.read(META_MAX), b""):
                    hashed.update(chunk)
            node[parts[-1]] = (b"100755" if row.mode & 0o111 else b"100644", hashed.digest())
    def tree(node):
        rows = []
        for name, value in node.items():
            encoded = name.encode("utf-8")
            if isinstance(value, dict):
                rows.append((encoded + b"/", b"40000", encoded, tree(value)))
            else:
                rows.append((encoded, value[0], encoded, value[1]))
        raw = b"".join(mode + b" " + name + b"\0" + digest for _, mode, name, digest in sorted(rows))
        return hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).digest()
    return tree(root).hex()


def source_policy(core):
    path = Path(core) / "scripts/verify-lab-release.py"
    safe_file(path)
    values = {}
    for node in ast.parse(path.read_bytes()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in ("COMPILED_FIXED", "COMPILED_ROOTS"):
            values[node.targets[0].id] = ast.literal_eval(node.value)
    need(set(values) == {"COMPILED_FIXED", "COMPILED_ROOTS"}, "published compiled selector missing")
    need(isinstance(values["COMPILED_FIXED"], set) and isinstance(values["COMPILED_ROOTS"], tuple),
         "published compiled selector type differs")
    return values


def compiler_origin(pin, role, sdk, sdk_rows, source, source_rows, core):
    """Legacy single-origin SDKs stay valid; mixed origin requires signed, pinned evidence."""
    origin = pin["compiler"].get("origin")
    explicit = {"producerCommit", "producerTree", "sourceInputsSHA256", "sourceEquivalence"}
    if origin is None:
        need(not (set(role) & explicit) and EQUIVALENCE_PATH not in sdk_rows,
             "explicit GNU origin requires a pinned source-equivalence contract")
        return {"mode": "legacy-single-origin", "producerCommit": GNU_RECEIPT_AUTHORITIES[pin["compiler"]["producerReceiptSha256"]]["commit"],
                "producerReceiptSha256": pin["compiler"]["producerReceiptSha256"]}
    need(role.get("producerCommit") == origin["producerCommit"] and role.get("producerTree") == origin["producerTree"]
         and role.get("sourceInputsSHA256") == origin["sourceInputsSha256"]
         and role.get("sourceEquivalence") == {"path": EQUIVALENCE_PATH, "sha256": origin["equivalenceSha256"],
             "rootAcceptanceSHA256": origin["rootAcceptanceSha256"]}, "signed GNU mixed-origin role differs")
    raw = member_bytes(sdk, sdk_rows, EQUIVALENCE_PATH)
    need(hashlib.sha256(raw).hexdigest() == origin["equivalenceSha256"], "signed GNU equivalence bytes differ")
    value = strict_json(raw)
    need(set(value) == {"schema", "kind", "compiler", "producer", "consumer", "selection", "rootAcceptanceSHA256",
         "oldProducerRelabelled", "freshCompilerBuildOrRuntimeClaimed"} and type(value["schema"]) is int
         and value["schema"] == 1 and value["kind"] == "retained-GNU-selected-source-equivalence-v1"
         and value["rootAcceptanceSHA256"] == origin["rootAcceptanceSha256"]
         and value["oldProducerRelabelled"] is False and value["freshCompilerBuildOrRuntimeClaimed"] is False,
         "GNU equivalence authority/scope differs")
    need(value["consumer"] == {"commit": pin["producerCommit"], "tree": pin["producerTree"],
         "sourceInputsSHA256": pin["sourceInputsSha256"], "version": pin["version"]}
         and value["compiler"] == {"bytes": pin["compiler"]["bytes"], "sha256": pin["compiler"]["sha256"],
             "target": COMPILER_TARGET, "version": pin["version"]}, "GNU equivalence consumer/compiler differs")
    producer = value["producer"]
    need(set(producer) == {"commit", "tree", "sourceInputsSHA256", "workerReceiptSHA256", "collectorReceiptSHA256",
         "selectedGraphSHA256", "normalInstallReceiptSHA256"}
         and producer["commit"] == origin["producerCommit"] and producer["tree"] == origin["producerTree"]
         and producer["sourceInputsSHA256"] == origin["sourceInputsSha256"]
         and producer["workerReceiptSHA256"] == pin["compiler"]["producerReceiptSha256"]
         and all(hex_value(producer[key], 64) for key in ("collectorReceiptSHA256", "selectedGraphSHA256", "normalInstallReceiptSHA256")),
         "GNU retained producer/receipt differs")
    selected = value["selection"]
    expected = {name for name in source_rows if name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml")
                or name.startswith(("crates/foxcore-api/", "crates/foxcore-route/"))}
    need(set(selected) == {"localPackages", "normalBuildPackageCount", "sourceFileCount", "sourceFiles",
         "customBuildTargetsOrFeatures", "onlyProductionEnvironmentMacro"}
         and selected["localPackages"] == ["foxcore-api", "foxcore-route"]
         and type(selected["normalBuildPackageCount"]) is int and selected["normalBuildPackageCount"] == 68
         and type(selected["sourceFileCount"]) is int and selected["sourceFileCount"] == len(expected) == 52
         and set(selected["sourceFiles"]) == expected and selected["customBuildTargetsOrFeatures"] is False
         and selected["onlyProductionEnvironmentMacro"] == "CARGO_PKG_VERSION=" + pin["version"],
         "GNU exact selected-input closure differs")
    with tarfile.open(source, "r:*") as archive:
        for name, row in selected["sourceFiles"].items():
            member = source_rows[name]
            need(set(row) == {"bytes", "mode", "sha256"} and type(row["bytes"]) is int and row["bytes"] == member.size
                 and type(row["mode"]) is int and row["mode"] == member.mode & 0o777 and hex_value(row["sha256"], 64),
                 "GNU selected source metadata differs")
            with archive.extractfile(member) as stream:
                need(hashlib.file_digest(stream, "sha256").hexdigest() == row["sha256"], "GNU signed selected source bytes differ")
            current = Path(core) / name
            info = safe_file(current, max(1, row["bytes"]))
            # Git records owner execute; checkout umask may remove other permission bits.
            need(info.st_size == row["bytes"] and bool(info.st_mode & stat.S_IXUSR) == bool(row["mode"] & stat.S_IXUSR)
                 and file_hash(current) == row["sha256"] and unchanged_file(current, info), "GNU delivery selected source differs")
    return {"mode": origin["mode"], "producerCommit": origin["producerCommit"], "consumerCommit": pin["producerCommit"],
            "equivalenceSha256": origin["equivalenceSha256"], "sourceFileCount": 52, "freshCompilerProductionClaimed": False}


def inspect_payload(pin, core, directory):
    import tomllib
    validate_pin(pin)
    paths = checked_assets(pin, directory)
    sdk, source = paths["sdk"], paths["source"]
    sdk_rows, source_rows = tar_index(sdk), tar_index(source)
    need(producer_tree(source, source_rows) == pin["producerTree"], "signed source archive producer tree differs")
    native_raw = member_bytes(sdk, sdk_rows, "metadata/NATIVE-RELEASE.json")
    compiled_raw = member_bytes(sdk, sdk_rows, "metadata/compiled-inputs.json")
    payload_raw = member_bytes(sdk, sdk_rows, "payload/MANIFEST.json")
    need(hashlib.sha256(native_raw).hexdigest() == pin["nativeManifestSha256"]
         and hashlib.sha256(compiled_raw).hexdigest() == pin["compiledInputsSha256"]
         and hashlib.sha256(payload_raw).hexdigest() == pin["payloadManifestSha256"], "native role metadata hash differs")
    native, compiled, payload = map(strict_json, (native_raw, compiled_raw, payload_raw))
    need(type(native.get("schema")) is int and native["schema"] == 1
         and native.get("kind") == "owner-authorized-native-Core-SDK-release"
         and native.get("version") == pin["version"] and native.get("sourceCommit") == pin["sourceCommit"]
         and native.get("nativeProducerCommit") == pin["producerCommit"]
         and native.get("nativeProducerTree") == pin["producerTree"]
         and native.get("sourceInputsSHA256") == pin["sourceInputsSha256"]
         and native.get("compiledInputsSHA256") == pin["compiledInputsSha256"]
         and type(native.get("compiledInputCount")) is int
         and native.get("compiledInputCount") == pin["compiledInputCount"]
         and native.get("sourceArchive") == {"name": pin["assets"]["source"]["name"], "sha256": pin["assets"]["source"]["sha256"]}
         and native.get("fullLabGatePassClaimed") is False, "native source/delivery/producer contract differs")
    role = native.get("GNUCompiler", {})
    need(role.get("path") == pin["compiler"]["path"] and role.get("sha256") == pin["compiler"]["sha256"]
         and role.get("target") == COMPILER_TARGET and role.get("version") == pin["version"]
         and role.get("producerReceiptSHA256") == pin["compiler"]["producerReceiptSha256"],
         "authenticated GNU producer role differs")
    need(type(compiled.get("schema")) is int and compiled["schema"] == 1
         and set(compiled) == {"schema", "producer_commit", "files"}
         and compiled["producer_commit"] == pin["producerCommit"]
         and isinstance(compiled["files"], dict) and len(compiled["files"]) == pin["compiledInputCount"],
         "compiled source manifest identity differs")
    policy = source_policy(core)
    public_paths = set(policy["COMPILED_FIXED"])
    for prefix in policy["COMPILED_ROOTS"]:
        portable(prefix.rstrip("/"))
        root = Path(core) / prefix
        if root.exists():
            need(root.is_dir() and not root.is_symlink(), "linked compiled source root")
            public_paths.update(path.relative_to(core).as_posix() for path in root.rglob("*") if path.is_file() or path.is_symlink())
    need(public_paths == set(compiled["files"]), "published compiled path set differs")
    with tarfile.open(source, "r:*") as archive:
        for name, expected in compiled["files"].items():
            portable(name)
            need(hex_value(expected, 64) and name in source_rows, "compiled source pin missing/unbound")
            row = source_rows[name]
            with archive.extractfile(row) as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            need(actual == expected, "signed producer source differs: " + name)
            path = Path(core) / name
            info = safe_file(path, max(1, row.size))
            need(info.st_size == row.size and bool(info.st_mode & 0o111) == bool(row.mode & 0o111)
                 and file_hash(path) == expected and unchanged_file(path, info), "signed delivery source differs: " + name)
    need("Cargo.lock" in compiled["files"], "compiled Cargo lock binding missing")
    lock_raw = member_bytes(sdk, sdk_rows, "payload/Cargo.lock")
    need(hashlib.sha256(lock_raw).hexdigest() == compiled["files"]["Cargo.lock"], "payload Cargo lock differs")
    source_toml = tomllib.loads(member_bytes(source, source_rows, "Cargo.toml").decode())
    need(source_toml["workspace"]["package"]["version"] == pin["version"], "producer source version differs")
    need(payload.get("manifest_version") == 2 and type(payload["manifest_version"]) is int
         and payload.get("core_version") == pin["version"]
         and payload.get("git") == {"commit": pin["producerCommit"], "dirty": False}
         and payload["git"]["dirty"] is False
         and payload.get("metadata_source") == {"commit": pin["sourceCommit"], "dirty": False}
         and payload["metadata_source"]["dirty"] is False
         and payload.get("build_inputs", {}).get("cargo_lock_sha256") == compiled["files"]["Cargo.lock"],
         "payload source/producer/version manifest differs")
    compiler = member_bytes(sdk, sdk_rows, COMPILER_PATH, 16 * META_MAX)
    need(len(compiler) == pin["compiler"]["bytes"] and sdk_rows[COMPILER_PATH].mode & 0o111
         and hashlib.sha256(compiler).hexdigest() == pin["compiler"]["sha256"]
         and len(compiler) >= 64 and compiler[:6] == b"\x7fELF\x02\x01"
         and struct.unpack_from("<H", compiler, 18)[0] == 62, "native GNU compiler ELF/bytes/hash differs")
    origin = compiler_origin(pin, role, sdk, sdk_rows, source, source_rows, core)
    return {"compilerSha256": pin["compiler"]["sha256"], "compilerPath": COMPILER_PATH,
            "compilerBytes": len(compiler), "compilerTarget": COMPILER_TARGET,
            "sourceCommit": pin["sourceCommit"], "producerCommit": pin["producerCommit"],
            "compilerOrigin": origin,
            "scope": "native-SDK compiler admission only", "fullLabAcceptanceClaimed": False,
            "DBCompilerCutoverQualificationInSDK": native.get("DBCompilerCutoverQualification")}


def command(argv, core, env=None):
    environment = {key: value for key, value in os.environ.items()
                   if not key.endswith("_TOKEN") and not key.startswith("GIT_TRACE") and key != "GIT_CURL_VERBOSE"}
    environment.update(GIT_OPTIONAL_LOCKS="0")
    if env:
        environment.update(env)
    process = subprocess.run(list(map(str, argv)), cwd=core, env=environment, capture_output=True, timeout=60)
    need(len(process.stdout) + len(process.stderr) <= META_MAX and process.returncode == 0,
         "owner signature/source command failed")
    return process.stdout, process.stderr


def owner_status(raw, allowed):
    rows = raw.decode().splitlines()
    forbidden = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYREVOKED", "NO_PUBKEY"}
    need(not any(len(row.split()) > 1 and row.split()[0] == "[GNUPG:]" and row.split()[1] in forbidden for row in rows),
         "invalid/expired/revoked owner signature")
    valid = [row.split() for row in rows if row.startswith("[GNUPG:] VALIDSIG ")]
    need(len(valid) == 1 and len(valid[0]) == 12
         and (valid[0][2].upper(), valid[0][11].upper()) in allowed and valid[0][9] in {"8", "9", "10"},
         "exact authorized owner signature and SHA256-or-stronger required")
    return {"signer": valid[0][2].upper(), "primary": valid[0][11].upper()}


def owner_context(pin, core, root):
    keys, fingerprints = Path(core) / "config/release-signers.asc", Path(core) / "config/release-signing-fingerprints.txt"
    for path, expected in [(keys, pin["policy"]["keysSha256"]), (fingerprints, pin["policy"]["fingerprintsSha256"])]:
        safe_file(path)
        need(file_hash(path) == expected, "pinned owner signing policy differs")
    allowed = set()
    for row in fingerprints.read_text().splitlines():
        parts = row.split()
        need(len(parts) == 2 and all(re.fullmatch("[0-9A-Fa-f]{40}", value) for value in parts),
             "invalid owner fingerprint policy")
        allowed.add(tuple(value.upper() for value in parts))
    need(allowed, "empty owner policy")
    env = {"GNUPGHOME": str(root)}
    # A public verification ring needs no agent or access to an owner's signing home.
    (root / "gpg.conf").write_text("no-auto-key-retrieve\nno-autostart\n")
    command(["gpg", "--batch", "--no-autostart", "--dearmor", "--output", root / "pubring.gpg", keys], core, env)
    return env, allowed


def authenticate_source(pin, core):
    core = Path(core)
    need(core.is_dir() and not core.is_symlink() and not core.stat().st_mode & 0o022, "safe exact Core checkout required")
    with tempfile.TemporaryDirectory(prefix="db-native-owner-") as temporary:
        env, allowed = owner_context(pin, core, Path(temporary))
        git = ["git", "-c", "gpg.format=openpgp", "-c", "gpg.program=gpg", "-c", "gpg.minTrustLevel=undefined"]
        head, _ = command([*git, "rev-parse", "HEAD"], core, env)
        tree, _ = command([*git, "rev-parse", "HEAD^{tree}"], core, env)
        status, _ = command([*git, "status", "--porcelain"], core, env)
        need(head.decode().strip() == pin["sourceCommit"] and tree.decode().strip() == pin["sourceTree"] and not status,
             "exact clean signed Core delivery checkout differs")
        out, err = command([*git, "verify-commit", "--raw", pin["sourceCommit"]], core, env)
        signature = owner_status(out + err, allowed)
        resolved, _ = command([*git, "rev-parse", "refs/tags/" + pin["releaseTag"] + "^{commit}"], core, env)
        need(resolved.decode().strip() == pin["sourceCommit"], "actual Core release tag source differs")
        kind, _ = command([*git, "cat-file", "-t", "refs/tags/" + pin["releaseTag"]], core, env)
        if kind.decode().strip() == "tag":
            out, err = command([*git, "verify-tag", "--raw", pin["releaseTag"]], core, env)
            owner_status(out + err, allowed)
        else:
            need(kind.decode().strip() == "commit", "unsupported release tag object")
    return {"sourceCommit": pin["sourceCommit"], "sourceTree": pin["sourceTree"], "ownerSignature": signature,
            "releaseTag": pin["releaseTag"]}


def verify_detached(pin, core, signature, subject):
    safe_file(signature)
    safe_file(subject, ARCHIVE_MAX if subject.name == pin["assets"]["source"]["name"] else META_MAX)
    with tempfile.TemporaryDirectory(prefix="db-native-detached-") as temporary:
        env, allowed = owner_context(pin, core, Path(temporary))
        out, err = command(["gpg", "--batch", "--no-auto-key-retrieve", "--status-fd=1", "--verify", signature, subject],
                           core, env)
        return owner_status(out + err, allowed)


def checksum_list(pin, paths):
    raw = paths["checksums"].read_text()
    rows = {}
    for line in raw.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]{0,159})", line)
        need(match is not None and match.group(2) not in rows, "invalid/duplicate signed checksum line")
        rows[match.group(2)] = match.group(1)
    expected = {pin["assets"][role]["name"]: pin["assets"][role]["sha256"]
                for role in ("sdk", "source", "sourceSignature")}
    need(rows == expected, "signed checksum asset set differs")


def describe(pin):
    validate_pin(pin)
    return {"family": "native-sdk", "release_tag": pin["releaseTag"], "source_commit": pin["sourceCommit"],
            "producer_commit": pin["producerCommit"], "release_asset": pin["assets"]["sdk"]["name"],
            "archive_bytes": pin["assets"]["sdk"]["bytes"], "archive_sha256": pin["assets"]["sdk"]["sha256"],
            "compiler_path": COMPILER_PATH, "assets": list(pin["assets"].values())}


def verify_native(pin, core, directory, output):
    validate_pin(pin)
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FileExistsError("new native compiler output required; existing data preserved")
    authenticate_source(pin, core)
    paths = checked_assets(pin, directory)
    checksums_signature = verify_detached(pin, core, paths["checksumsSignature"], paths["checksums"])
    checksum_list(pin, paths)
    source_signature = verify_detached(pin, core, paths["sourceSignature"], paths["source"])
    result = inspect_payload(pin, core, directory)
    rows = tar_index(paths["sdk"])
    compiler = member_bytes(paths["sdk"], rows, COMPILER_PATH, 16 * META_MAX)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".native-compiler-", dir=output.parent))
    try:
        target = temporary / COMPILER_PATH
        target.parent.mkdir(parents=True, mode=0o700)
        with target.open("xb") as stream:
            stream.write(compiler)
        target.chmod(0o700)
        need(file_hash(target) == pin["compiler"]["sha256"], "fresh compiler extraction hash differs")
        temporary.rename(output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return dict(result, compilerExecuted=False, checksumsOwnerSignature=checksums_signature,
                sourceArchiveOwnerSignature=source_signature)
