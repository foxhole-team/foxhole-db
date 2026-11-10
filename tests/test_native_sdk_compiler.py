"""Native-SDK admission fixtures; target binaries, private keys, Git and signing are never run."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import contextlib

ROOT = Path(__file__).resolve().parents[1]


class NativeSDKCompilerTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "tools/native_sdk_compiler.py"
        self.assertTrue(path.is_file(), "strict native-SDK admission is missing")
        spec = importlib.util.spec_from_file_location("native_sdk_test", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def archive(self, path, members):
        with tarfile.open(path, "w") as archive:
            for name, raw, mode, kind in members:
                member = tarfile.TarInfo(name); member.mode = mode; member.size = len(raw)
                if kind == "symlink": member.type = tarfile.SYMTYPE; member.linkname = "/outside"
                elif kind == "hardlink": member.type = tarfile.LNKTYPE; member.linkname = "outside"
                archive.addfile(member, io.BytesIO(raw) if member.isfile() else None)

    def fixture(self, root):
        core = root / "core"; core.mkdir()
        source_files = {"Cargo.toml": b'[workspace.package]\nversion="1.0.3"\n',
                        "Cargo.lock": b"owned lock\n", "crates/foxcore-route/src/lib.rs": b"owned code\n"}
        for name, raw in source_files.items():
            path = core / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        (core / "scripts").mkdir()
        (core / "scripts/verify-lab-release.py").write_text("COMPILED_FIXED={'Cargo.toml','Cargo.lock'}\nCOMPILED_ROOTS=('crates/',)\n")
        files = {name: hashlib.sha256(raw).hexdigest() for name, raw in source_files.items()}
        compiled = {"schema": 1, "producer_commit": "b" * 40, "files": files}
        compiled_raw = (json.dumps(compiled, sort_keys=True) + "\n").encode()
        assets = root / "assets"; assets.mkdir()
        source_name, sdk_name = "owned-source.tar", "owned-sdk.tar"
        self.archive(assets / source_name, [(name, raw, 0o644, "file") for name, raw in source_files.items()])
        producer_tree = self.module.producer_tree(assets / source_name, self.module.tar_index(assets / source_name))
        source_hash = hashlib.sha256((assets / source_name).read_bytes()).hexdigest()
        binary = bytearray(64); binary[:6] = b"\x7fELF\x02\x01"; struct.pack_into("<H", binary, 18, 62)
        compiler_hash = hashlib.sha256(binary).hexdigest()
        native = {"schema": 1, "kind": "owner-authorized-native-Core-SDK-release", "version": "1.0.3",
                  "sourceCommit": "a" * 40, "nativeProducerCommit": "b" * 40, "nativeProducerTree": producer_tree,
                  "sourceInputsSHA256": "d" * 64, "compiledInputsSHA256": hashlib.sha256(compiled_raw).hexdigest(),
                  "compiledInputCount": len(files), "sourceArchive": {"name": source_name, "sha256": source_hash},
                  "fullLabGatePassClaimed": False,
                  "GNUCompiler": {"path": "payload/bin/linux-x86_64/foxcore-dns-compile", "sha256": compiler_hash,
                                  "version": "1.0.3", "target": "x86_64-unknown-linux-gnu",
                                  "producerReceiptSHA256": "e" * 64}}
        manifest = {"manifest_version": 2, "core_version": "1.0.3",
                    "git": {"commit": "b" * 40, "dirty": False},
                    "metadata_source": {"commit": "a" * 40, "dirty": False},
                    "build_inputs": {"cargo_lock_sha256": files["Cargo.lock"]}}
        native_raw = (json.dumps(native, sort_keys=True) + "\n").encode()
        manifest_raw = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        self.archive(assets / sdk_name, [("metadata/NATIVE-RELEASE.json", native_raw, 0o644, "file"),
                     ("metadata/compiled-inputs.json", compiled_raw, 0o644, "file"),
                     ("payload/MANIFEST.json", manifest_raw, 0o644, "file"),
                     ("payload/Cargo.lock", source_files["Cargo.lock"], 0o644, "file"),
                     ("payload/bin/linux-x86_64/foxcore-dns-compile", bytes(binary), 0o755, "file")])
        for name in ("owned-source.tar.asc", "SHA256SUMS.asc"):
            (assets / name).write_bytes(b"owned synthetic signature\n")
        sums = "".join(hashlib.sha256((assets / name).read_bytes()).hexdigest() + "  " + name + "\n"
                       for name in sorted([sdk_name, source_name, "owned-source.tar.asc"]))
        (assets / "SHA256SUMS").write_text(sums)
        def asset(name):
            raw = (assets / name).read_bytes()
            return {"name": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        pin = {"schema": 2, "family": "native-sdk", "version": "1.0.3", "releaseTag": "v1.0.3",
               "sourceCommit": "a" * 40, "sourceTree": "f" * 40, "producerCommit": "b" * 40,
               "producerTree": producer_tree, "sourceInputsSha256": "d" * 64,
               "compiledInputsSha256": hashlib.sha256(compiled_raw).hexdigest(), "compiledInputCount": len(files),
               "nativeManifestSha256": hashlib.sha256(native_raw).hexdigest(),
               "payloadManifestSha256": hashlib.sha256(manifest_raw).hexdigest(),
               "policy": {"keysSha256": "1" * 64, "fingerprintsSha256": "2" * 64},
               "assets": {"sdk": asset(sdk_name), "source": asset(source_name),
                          "sourceSignature": asset("owned-source.tar.asc"), "checksums": asset("SHA256SUMS"),
                          "checksumsSignature": asset("SHA256SUMS.asc")},
               "compiler": {"path": "payload/bin/linux-x86_64/foxcore-dns-compile", "sha256": compiler_hash,
                            "bytes": 64, "target": "x86_64-unknown-linux-gnu", "producerReceiptSha256": "e" * 64}}
        # Test-only synthetic receipt and exact legacy archive authority. Production
        # has a closed actual Core103 exception and never accepts these values.
        self.module.GNU_RECEIPT_AUTHORITIES["e" * 64] = {"commit": pin["producerCommit"], "tree": pin["producerTree"],
            "sourceInputsSha256": pin["sourceInputsSha256"], "version": pin["version"],
            "sha256": pin["compiler"]["sha256"], "bytes": pin["compiler"]["bytes"]}
        self.module.LEGACY_GNU_RECEIPT_SHA = "e" * 64
        self.module.LEGACY_NATIVE_SDK_SHA = pin["assets"]["sdk"]["sha256"]
        return pin, core, assets

    def test_bound_schema2_and_exact_payload_source_chain_are_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets = self.fixture(Path(temporary))
            self.assertEqual(pin, self.module.validate_pin(pin))
            result = self.module.inspect_payload(pin, core, assets)
            self.assertEqual(pin["compiler"]["sha256"], result["compilerSha256"])
            self.assertFalse(result["fullLabAcceptanceClaimed"])

    def test_safe_owner_only_source_matches_git_nonexec_mode_but_exec_or_writable_change_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets = self.fixture(Path(temporary))
            path = core / "crates/foxcore-route/src/lib.rs"
            path.chmod(0o600)
            self.module.inspect_payload(pin, core, assets)
            for mode in (0o755, 0o666):
                path.chmod(mode)
                with self.assertRaises(ValueError): self.module.inspect_payload(pin, core, assets)
            path.chmod(0o600)
            original = self.module.file_hash
            def change_during_read(selected):
                value = original(selected)
                if Path(selected) == path: path.chmod(0o644)
                return value
            with patch.object(self.module, "file_hash", side_effect=change_during_read):
                with self.assertRaisesRegex(ValueError, "signed delivery source differs"):
                    self.module.inspect_payload(pin, core, assets)

        # Retained GNU delivery uses Git owner-exec semantics, including umask077.
        for producer_mode in (0o644, 0o755):
            with self.subTest(producer_mode=oct(producer_mode)), tempfile.TemporaryDirectory() as temporary:
                pin, core, assets, witness, native, _ = self.mixed_fixture(Path(temporary), source_mode=producer_mode)
                producer_rows = copy.deepcopy(witness["selection"]["sourceFiles"])
                for name, row in producer_rows.items():
                    (core / name).chmod(0o700 if row["mode"] & 0o100 else 0o600)
                self.module.inspect_payload(pin, core, assets)
                path = core / "crates/foxcore-route/src/lib.rs"
                checkout_mode = 0o700 if producer_mode & 0o100 else 0o600
                source_path = assets / pin["assets"]["source"]["name"]
                sdk_path = assets / pin["assets"]["sdk"]["name"]
                args = (pin, native["GNUCompiler"], sdk_path, self.module.tar_index(sdk_path),
                        source_path, self.module.tar_index(source_path), core)
                for bad_mode in (checkout_mode ^ 0o100, checkout_mode | 0o020, checkout_mode | 0o002):
                    path.chmod(bad_mode)
                    with self.subTest(mode=oct(bad_mode)), self.assertRaises(ValueError): self.module.compiler_origin(*args)
                path.chmod(checkout_mode)
                body = path.read_bytes(); path.write_bytes(b"x" * len(body))
                with self.assertRaisesRegex(ValueError, "GNU delivery selected source differs"): self.module.compiler_origin(*args)
                path.write_bytes(body)
                original = self.module.file_hash
                def change_checkout_during_read(selected):
                    value = original(selected)
                    if Path(selected) == path: path.chmod(checkout_mode ^ 0o200)
                    return value
                with patch.object(self.module, "file_hash", side_effect=change_checkout_during_read):
                    with self.assertRaisesRegex(ValueError, "GNU delivery selected source differs"): self.module.compiler_origin(*args)
                self.assertEqual(producer_rows, witness["selection"]["sourceFiles"])

    def test_null_bool_unknown_and_unbound_schema2_fields_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, _, _ = self.fixture(Path(temporary))
            for field in ("sourceCommit", "sourceTree", "producerTree", "compiledInputsSha256"):
                bad = copy.deepcopy(pin); bad[field] = None
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.module.validate_pin(bad)
            bad = copy.deepcopy(pin); bad["schema"] = True
            with self.assertRaises(ValueError): self.module.validate_pin(bad)
            bad = copy.deepcopy(pin); bad["unexpected"] = 1
            with self.assertRaises(ValueError): self.module.validate_pin(bad)

    def test_tar_symlink_hardlink_traversal_duplicate_and_casefold_refuse(self):
        for bad in ("../escape", "/escape", "symlink", "hardlink", "duplicate", "casefold", "prefix"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "owned.tar"
                members = [("ok", b"owned", 0o644, "file")]
                if bad in ("symlink", "hardlink"): members += [(bad, b"", 0o644, bad)]
                elif bad == "duplicate": members += [members[0]]
                elif bad == "casefold": members += [("OK", b"owned", 0o644, "file")]
                elif bad == "prefix": members += [("ok/child", b"owned", 0o644, "file")]
                else: members += [(bad, b"owned", 0o644, "file")]
                self.archive(path, members)
                with self.assertRaises(ValueError): self.module.tar_index(path)

    def test_owner_status_rejects_wrong_signer_expired_bad_and_weak_hash(self):
        allowed = {("A" * 40, "B" * 40)}
        good = "[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-11-09 1 0 4 0 22 8 00 " + "B" * 40 + "\n"
        self.module.owner_status(good.encode(), allowed)
        for raw in [good.replace("A" * 40, "C" * 40), good + "[GNUPG:] EXPKEYSIG bad\n",
                    good + "[GNUPG:] BADSIG bad\n", good.replace("22 8 00", "22 2 00")]:
            with self.assertRaises(ValueError): self.module.owner_status(raw.encode(), allowed)

    def test_payload_tampering_wrong_compiler_target_or_hash_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets = self.fixture(Path(temporary))
            for change in ("hash", "target", "path"):
                bad = copy.deepcopy(pin)
                bad["compiler"][{"hash": "sha256", "target": "target", "path": "path"}[change]] = {"hash": "0" * 64, "target": "aarch64-unknown-linux-gnu", "path": "../compiler"}[change]
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.module.validate_pin(bad) if change != "hash" else self.module.inspect_payload(bad, core, assets)
            (assets / pin["assets"]["sdk"]["name"]).write_bytes(b"tampered")
            with self.assertRaises(ValueError): self.module.inspect_payload(pin, core, assets)

    def test_signature_failure_precedes_executable_output_and_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pin, core, assets = self.fixture(root); output = root / "verified"
            with patch.object(self.module, "authenticate_source", return_value={"scope": "owned mock auth"}), \
                 patch.object(self.module, "verify_detached", side_effect=ValueError("owned bad signature")):
                with self.assertRaises(ValueError): self.module.verify_native(pin, core, assets, output)
            self.assertFalse(output.exists())
            output.mkdir(); (output / "owner-data").write_bytes(b"keep")
            with self.assertRaises(FileExistsError): self.module.verify_native(pin, core, assets, output)
            self.assertEqual(b"keep", (output / "owner-data").read_bytes())

    def test_valid_chain_extracts_only_verified_compiler_atomically_without_running_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pin, core, assets = self.fixture(root); output = root / "verified"
            with patch.object(self.module, "authenticate_source", return_value={"scope": "owned mock auth"}), \
                 patch.object(self.module, "verify_detached", return_value={"scope": "owned mock detached auth"}) as signatures:
                result = self.module.verify_native(pin, core, assets, output)
            self.assertEqual(2, signatures.call_count)
            compiler = output / pin["compiler"]["path"]
            self.assertEqual(pin["compiler"]["sha256"], hashlib.sha256(compiler.read_bytes()).hexdigest())
            self.assertTrue(compiler.stat().st_mode & 0o111)
            self.assertEqual([pin["compiler"]["path"]], sorted(str(p.relative_to(output)) for p in output.rglob("*") if p.is_file()))
            self.assertFalse(result["compilerExecuted"])

    def test_published_source_mutation_and_wrong_native_producer_binding_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets = self.fixture(Path(temporary))
            changed = core / "crates/foxcore-route/src/lib.rs"
            changed.write_bytes(b"changed delivery code\n")
            with self.assertRaises(ValueError): self.module.inspect_payload(pin, core, assets)
            changed.write_bytes(b"owned code\n")
            sdk = assets / pin["assets"]["sdk"]["name"]
            original = []
            with tarfile.open(sdk) as archive:
                for member in archive:
                    original.append((member.name, archive.extractfile(member).read(), member.mode, "file"))
            for field in ("sourceCommit", "nativeProducerCommit", "nativeProducerTree", "sourceInputsSHA256"):
                bad = copy.deepcopy(pin); rows = copy.deepcopy(original)
                for index, row in enumerate(rows):
                    if row[0] == "metadata/NATIVE-RELEASE.json":
                        value = json.loads(row[1]); value[field] = "0" * len(value[field])
                        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
                        rows[index] = (row[0], raw, row[2], row[3]); bad["nativeManifestSha256"] = hashlib.sha256(raw).hexdigest()
                self.archive(sdk, rows)
                bad["assets"]["sdk"].update(bytes=sdk.stat().st_size, sha256=hashlib.sha256(sdk.read_bytes()).hexdigest())
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.module.inspect_payload(bad, core, assets)

    def test_checksum_asset_set_and_duplicate_lines_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, _, assets = self.fixture(Path(temporary))
            paths = {role: assets / value["name"] for role, value in pin["assets"].items()}
            self.module.checksum_list(pin, paths)
            sums = paths["checksums"]; original = sums.read_text()
            for content in [original + original.splitlines()[0] + "\n", original.replace("owned-sdk.tar", "../owned-sdk.tar"),
                            original + "0" * 64 + "  unexpected.tar\n"]:
                sums.write_text(content)
                with self.assertRaises(ValueError): self.module.checksum_list(pin, paths)

    def test_native_asset_hardlink_and_symlink_refuse_before_payload_read(self):
        for kind in ("hardlink", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                pin, _, assets = self.fixture(Path(temporary))
                file = assets / pin["assets"]["sdk"]["name"]
                if kind == "hardlink": os.link(file, assets / "extra-owned-link")
                else:
                    actual = assets / "owned-actual.tar"; file.rename(actual); file.symlink_to(actual)
                with self.assertRaises(ValueError): self.module.checked_assets(pin, assets)

    def test_source_auth_requires_exact_checkout_signature_and_release_tag(self):
        allowed = {("A" * 40, "B" * 40)}
        good = ("[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-11-09 1 0 4 0 22 8 00 " + "B" * 40 + "\n").encode()
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, _ = self.fixture(Path(temporary))
            for mode in ("valid", "dirty", "tree", "tag", "signature"):
                def fake(argv, directory, env=None):
                    if "verify-commit" in argv: return b"", good if mode != "signature" else b"[GNUPG:] BADSIG owned\n"
                    if "status" in argv: return (b" M file\n" if mode == "dirty" else b""), b""
                    if "cat-file" in argv: return b"commit\n", b""
                    selected = argv[-1]
                    if selected == "HEAD": return pin["sourceCommit"].encode() + b"\n", b""
                    if selected == "HEAD^{tree}": return (pin["sourceTree"] if mode != "tree" else "0" * 40).encode(), b""
                    return (pin["sourceCommit"] if mode != "tag" else "0" * 40).encode(), b""
                with patch.object(self.module, "owner_context", return_value=({}, allowed)), patch.object(self.module, "command", side_effect=fake):
                    if mode == "valid":
                        self.assertEqual(pin["sourceCommit"], self.module.authenticate_source(pin, core)["sourceCommit"])
                    else:
                        with self.subTest(mode=mode), self.assertRaises(ValueError):
                            self.module.authenticate_source(pin, core)

    def test_schema2_entrypoint_never_loads_legacy_full17_verifier(self):
        spec = importlib.util.spec_from_file_location("compiler_native_entry", ROOT / "verify-core-compiler.py")
        entry = importlib.util.module_from_spec(spec); spec.loader.exec_module(entry)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pin, core, _ = self.fixture(root); path = root / "pin.json"; path.write_text(json.dumps(pin))
            with patch.object(entry, "load_native", return_value=self.module), \
                 patch.object(entry, "load_verifier", side_effect=AssertionError("legacy full17 path used")), \
                 patch.object(self.module, "authenticate_source", return_value={"scope": "mock source auth"}), \
                 patch("sys.argv", ["verify-core-compiler.py", "describe", "--pin", str(path), "--core", str(core)]), \
                 contextlib.redirect_stdout(io.StringIO()):
                entry.main()

    def mixed_fixture(self, root, source_mode=0o644):
        pin, core, assets = self.fixture(root)
        source = {path.relative_to(core).as_posix(): path.read_bytes() for path in core.rglob("*")
                  if path.is_file() and "scripts/" not in path.relative_to(core).as_posix()}
        source.update({".cargo/config.toml": b"[net]\noffline=true\n", "rust-toolchain.toml": b"owned toolchain\n",
                       "crates/foxcore-api/src/lib.rs": b"owned API\n"})
        source.update({"crates/foxcore-route/src/fixture" + str(index) + ".rs": b"owned selected input\n" for index in range(46)})
        self.assertEqual(52, len(source))
        modes = dict.fromkeys(source, 0o644)
        modes["crates/foxcore-route/src/lib.rs"] = source_mode
        for name, raw in source.items():
            path = core / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw); path.chmod(modes[name])
        (core / "scripts/verify-lab-release.py").write_text("COMPILED_FIXED={'Cargo.toml','Cargo.lock','.cargo/config.toml','rust-toolchain.toml'}\nCOMPILED_ROOTS=('crates/',)\n")
        source_path = assets / pin["assets"]["source"]["name"]
        self.archive(source_path, [(name, raw, modes[name], "file") for name, raw in source.items()])
        pin["producerTree"] = self.module.producer_tree(source_path, self.module.tar_index(source_path))
        pin["assets"]["source"].update(bytes=source_path.stat().st_size, sha256=self.module.file_hash(source_path))
        sdk_path = assets / pin["assets"]["sdk"]["name"]
        with tarfile.open(sdk_path) as archive:
            members = {row.name: (archive.extractfile(row).read(), row.mode) for row in archive}
        native = json.loads(members["metadata/NATIVE-RELEASE.json"][0])
        compiled = {"schema": 1, "producer_commit": pin["producerCommit"],
                    "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in source.items()}}
        members["metadata/compiled-inputs.json"] = (json.dumps(compiled).encode(), 0o644)
        pin["compiledInputsSha256"] = hashlib.sha256(members["metadata/compiled-inputs.json"][0]).hexdigest()
        pin["compiledInputCount"] = len(source)
        native.update(nativeProducerTree=pin["producerTree"], compiledInputsSHA256=pin["compiledInputsSha256"],
                      compiledInputCount=len(source), sourceArchive={"name": pin["assets"]["source"]["name"],
                      "sha256": pin["assets"]["source"]["sha256"]})
        witness = {"schema": 1, "kind": "retained-GNU-selected-source-equivalence-v1", "rootAcceptanceSHA256": "7" * 64,
            "producer": {"commit": "c" * 40, "tree": "9" * 40, "sourceInputsSHA256": "8" * 64,
                "workerReceiptSHA256": pin["compiler"]["producerReceiptSha256"], "collectorReceiptSHA256": "6" * 64,
                "selectedGraphSHA256": "5" * 64, "normalInstallReceiptSHA256": "4" * 64},
            "consumer": {"commit": pin["producerCommit"], "tree": pin["producerTree"],
                "sourceInputsSHA256": pin["sourceInputsSha256"], "version": pin["version"]},
            "compiler": {key: pin["compiler"][key] for key in ("bytes", "sha256", "target")},
            "selection": {"localPackages": ["foxcore-api", "foxcore-route"], "normalBuildPackageCount": 68,
                "sourceFileCount": 52, "sourceFiles": {name: {"bytes": len(raw), "mode": modes[name],
                "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in source.items()},
                "customBuildTargetsOrFeatures": False, "onlyProductionEnvironmentMacro": "CARGO_PKG_VERSION=" + pin["version"]},
            "oldProducerRelabelled": False, "freshCompilerBuildOrRuntimeClaimed": False}
        witness["compiler"]["version"] = pin["version"]
        origin = {"mode": "retained-source-equivalence-v1", "producerCommit": "c" * 40, "producerTree": "9" * 40,
            "sourceInputsSha256": "8" * 64, "consumerCommit": pin["producerCommit"], "consumerTree": pin["producerTree"],
            "consumerSourceInputsSha256": pin["sourceInputsSha256"], "equivalencePath": self.module.EQUIVALENCE_PATH,
            "rootAcceptanceSha256": "7" * 64, "equivalenceSha256": "3" * 64}
        pin["compiler"]["origin"] = origin
        native["GNUCompiler"].update(producerCommit="c" * 40, producerTree="9" * 40, sourceInputsSHA256="8" * 64)
        def rewrite():
            raw = json.dumps(witness).encode()
            origin["equivalenceSha256"] = hashlib.sha256(raw).hexdigest()
            native["GNUCompiler"]["sourceEquivalence"] = {"path": self.module.EQUIVALENCE_PATH,
                "sha256": origin["equivalenceSha256"], "rootAcceptanceSHA256": origin["rootAcceptanceSha256"]}
            members[self.module.EQUIVALENCE_PATH] = (raw, 0o644)
            members["metadata/NATIVE-RELEASE.json"] = (json.dumps(native).encode(), 0o644)
            pin["nativeManifestSha256"] = hashlib.sha256(members["metadata/NATIVE-RELEASE.json"][0]).hexdigest()
            self.archive(sdk_path, [(name, raw, mode, "file") for name, (raw, mode) in members.items()])
            pin["assets"]["sdk"].update(bytes=sdk_path.stat().st_size, sha256=self.module.file_hash(sdk_path))
        rewrite()
        self.module.GNU_RECEIPT_AUTHORITIES["e" * 64].update(commit="c" * 40, tree="9" * 40, sourceInputsSha256="8" * 64)
        return pin, core, assets, witness, native, rewrite

    def test_explicit_retained_origin_accepts_same_selected_source_without_retag(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets, _, _, _ = self.mixed_fixture(Path(temporary))
            result = self.module.inspect_payload(pin, core, assets)
            self.assertEqual("c" * 40, result["compilerOrigin"]["producerCommit"])
            self.assertEqual("b" * 40, result["compilerOrigin"]["consumerCommit"])
            self.assertFalse(result["compilerOrigin"]["freshCompilerProductionClaimed"])

    def test_mixed_origin_cannot_fall_back_to_legacy(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets, _, _, _ = self.mixed_fixture(Path(temporary))
            del pin["compiler"]["origin"]
            with self.assertRaisesRegex(ValueError, "cannot be stripped"):
                self.module.inspect_payload(pin, core, assets)

    def test_mixed_origin_requires_the_actual_signed_witness_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets, _, _, _ = self.mixed_fixture(Path(temporary))
            path = assets / pin["assets"]["sdk"]["name"]
            with tarfile.open(path) as archive:
                members = [(row.name, archive.extractfile(row).read(), row.mode, "file") for row in archive
                           if row.name != self.module.EQUIVALENCE_PATH]
            self.archive(path, members)
            pin["assets"]["sdk"].update(bytes=path.stat().st_size, sha256=self.module.file_hash(path))
            with self.assertRaisesRegex(ValueError, "missing/bounded native role"):
                self.module.inspect_payload(pin, core, assets)

    def test_stripping_both_role_witness_and_pin_origin_cannot_create_legacy(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets, _, _, _ = self.mixed_fixture(Path(temporary))
            del pin["compiler"]["origin"]
            path = assets / pin["assets"]["sdk"]["name"]
            members = []
            with tarfile.open(path) as archive:
                for row in archive:
                    if row.name == self.module.EQUIVALENCE_PATH: continue
                    raw = archive.extractfile(row).read()
                    if row.name == "metadata/NATIVE-RELEASE.json":
                        native = json.loads(raw)
                        for key in ("producerCommit", "producerTree", "sourceInputsSHA256", "sourceEquivalence"):
                            del native["GNUCompiler"][key]
                        raw = json.dumps(native).encode(); pin["nativeManifestSha256"] = hashlib.sha256(raw).hexdigest()
                    members.append((row.name, raw, row.mode, "file"))
            self.archive(path, members)
            pin["assets"]["sdk"].update(bytes=path.stat().st_size, sha256=self.module.file_hash(path))
            with self.assertRaisesRegex(ValueError, "cannot be stripped"):
                self.module.inspect_payload(pin, core, assets)

    def test_receipt_hash_stripping_unknown_or_mislabelled_authority_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, _, _, _, _, _ = self.mixed_fixture(Path(temporary))
            for value in (None, "f" * 64, "0" * 64, self.module.LEGACY_GNU_RECEIPT_SHA):
                bad = copy.deepcopy(pin); bad["compiler"]["producerReceiptSha256"] = value
                if value == self.module.LEGACY_GNU_RECEIPT_SHA:
                    bad["compiler"]["origin"]["producerCommit"] = "a" * 40
                with self.subTest(value=value), self.assertRaises(ValueError): self.module.validate_pin(bad)
            bad = copy.deepcopy(pin); del bad["compiler"]["producerReceiptSha256"]
            with self.assertRaises(ValueError): self.module.validate_pin(bad)
            bad = copy.deepcopy(pin); bad["compiler"]["compilerOrigin"] = bad["compiler"].pop("origin")
            with self.assertRaises(ValueError): self.module.validate_pin(bad)

    def test_legacy_exception_requires_exact_qualified_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, _, _ = self.fixture(Path(temporary))
            bad = copy.deepcopy(pin); bad["assets"]["sdk"]["sha256"] = "a" * 64
            with self.assertRaisesRegex(ValueError, "cannot be stripped"): self.module.validate_pin(bad)

    def test_origin_pin_null_unknown_retag_and_consumer_mismatch_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, _, _, _, _, _ = self.mixed_fixture(Path(temporary))
            for field, value in (("producerCommit", pin["producerCommit"]), ("consumerCommit", "f" * 40),
                    ("consumerTree", None), ("rootAcceptanceSha256", "0" * 64), ("equivalencePath", "../proof"), ("extra", 1)):
                bad = copy.deepcopy(pin); bad["compiler"]["origin"][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError): self.module.validate_pin(bad)

    def test_signed_witness_rejects_wrong_scope_source_receipt_and_false_promotion(self):
        mutations = [lambda d: d.update(oldProducerRelabelled=True), lambda d: d.update(freshCompilerBuildOrRuntimeClaimed=True),
            lambda d: d["consumer"].update(commit="f" * 40), lambda d: d["producer"].update(workerReceiptSHA256="a" * 64),
            lambda d: d["selection"].update(normalBuildPackageCount=67), lambda d: d["selection"].update(customBuildTargetsOrFeatures=True),
            lambda d: d["selection"].update(localPackages=["foxcore-dns"]), lambda d: d.update(rootAcceptanceSHA256="a" * 64),
            lambda d: d["selection"]["sourceFiles"]["Cargo.lock"].update(sha256="a" * 64),
            lambda d: d["selection"]["sourceFiles"]["Cargo.lock"].update(mode=0o755),
            lambda d: d["selection"]["sourceFiles"].pop("Cargo.lock")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                pin, core, assets, witness, _, rewrite = self.mixed_fixture(Path(temporary))
                mutate(witness); rewrite()
                with self.assertRaises(ValueError): self.module.inspect_payload(pin, core, assets)

    def test_signed_role_must_bind_the_retained_producer(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin, core, assets, _, native, rewrite = self.mixed_fixture(Path(temporary))
            native["GNUCompiler"]["producerCommit"] = pin["producerCommit"]; rewrite()
            with self.assertRaisesRegex(ValueError, "mixed-origin role"):
                self.module.inspect_payload(pin, core, assets)


if __name__ == "__main__":
    unittest.main()
