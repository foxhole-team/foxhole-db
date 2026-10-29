import ast
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDERS = (
    "build-adguard-dns-filter.sh",
    "build-threat-intel.sh",
    "build-bridges.sh",
    "build-geoip.sh",
    "build-fingerprints.sh",
)


class BuilderOwnershipTests(unittest.TestCase):
    def test_retained_build_work_never_retains_a_materialized_signing_key(self):
        for name in BUILDERS:
            source = (ROOT / name).read_text()
            end = source.index("trap cleanup EXIT") + len("trap cleanup EXIT")
            for exit_code in (0, 17):
                with self.subTest(builder=name, exit=exit_code):
                    with tempfile.TemporaryDirectory(prefix="foxhole-key-cleanup-test-") as temporary:
                        owned = Path(temporary)
                        caller = owned / "caller"
                        caller.mkdir()
                        sentinel = caller / "owner-sentinel.txt"
                        sentinel.write_text("caller-owned\n")
                        supplied_key = caller / "owner.private.pem"
                        supplied_key.write_text("caller-owned key\n")
                        script = owned / "lifecycle.sh"
                        script.write_text(source[:end] + '\n' +
                                          'TEMP_KEY_PATH="$WORK_DIR/manifest.private.pem"\n' +
                                          'printf "synthetic fixture key\\n" > "$TEMP_KEY_PATH"\n' +
                                          'printf "%s\\n" "$WORK_DIR"\n' +
                                          f'exit {exit_code}\n')
                        environment = {"PATH": os.defpath, "WORK_DIR": str(caller),
                                       "OUT_DIR": str(owned / "out"), "FOXHOLE_DNS_ROOT": str(owned),
                                       "TMPDIR": str(owned), "KEEP_WORK_DIR": "true",
                                       "FOXHOLE_DNS_SIGNING_KEY": str(supplied_key)}
                        result = subprocess.run(["/bin/bash", str(script)], env=environment,
                                                capture_output=True, text=True, check=False, timeout=10)
                        self.assertEqual(exit_code, result.returncode, result.stderr)
                        self.assertEqual("caller-owned\n", sentinel.read_text())
                        self.assertEqual("caller-owned key\n", supplied_key.read_text())
                        child = Path(result.stdout.strip())
                        self.assertTrue(child.is_dir())
                        self.assertFalse((child / "manifest.private.pem").exists())

    def test_fallback_compiler_keeps_locked_dependencies(self):
        source = (ROOT / "build-adguard-dns-filter.sh").read_text()
        need = source[source.index("need() {"):source.index("need git")]
        resolver = source[source.index("resolve_compiler() {"):source.index("\nresolve_compiler\n")]
        with tempfile.TemporaryDirectory(prefix="foxhole-compiler-contract-") as temporary:
            owned = Path(temporary)
            core = owned / "core"
            core.mkdir()
            (core / "Cargo.toml").write_text("[workspace]\n")
            capture = owned / "cargo-args.txt"
            cargo = owned / "owned-cargo"
            cargo.write_text(
                '#!/bin/sh\n'
                'printf "%s\\n" "$@" > "$CAPTURE_ARGS"\n'
                'mkdir -p "$CARGO_TARGET_DIR/release"\n'
                'printf "#!/bin/sh\\nexit 0\\n" > "$CARGO_TARGET_DIR/release/foxcore-dns-compile"\n'
                'chmod +x "$CARGO_TARGET_DIR/release/foxcore-dns-compile"\n'
            )
            cargo.chmod(0o755)
            script = owned / "resolve.sh"
            script.write_text("set -euo pipefail\n" + need + resolver + "\nresolve_compiler\n")
            environment = {
                "PATH": os.defpath,
                "FOXCORE_DNS_COMPILE_BIN": str(owned / "missing-compiler"),
                "FOXCORE_ROOT": str(core),
                "CARGO_BIN": str(cargo),
                "CARGO_TARGET_DIR": str(owned / "target"),
                "CAPTURE_ARGS": str(capture),
            }
            result = subprocess.run(
                ["/bin/bash", str(script)], env=environment,
                capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("--locked", capture.read_text().splitlines())

    def test_exit_cleanup_preserves_caller_directory_and_sentinel(self):
        for name in BUILDERS:
            source = (ROOT / name).read_text()
            end = source.index("trap cleanup EXIT") + len("trap cleanup EXIT")
            prologue = source[:end]
            for exit_code in (0, 17):
                for keep in ("false", "true"):
                    with self.subTest(builder=name, exit=exit_code, keep=keep):
                        with tempfile.TemporaryDirectory(prefix="foxhole-owned-builder-test-") as temporary:
                            owned = Path(temporary)
                            caller = owned / "caller"
                            caller.mkdir()
                            sentinel = caller / "owner-sentinel.txt"
                            sentinel.write_text("owned fixture sentinel\n")
                            script = owned / "lifecycle.sh"
                            script.write_text(
                                prologue + f'\nprintf "%s\\n" "$WORK_DIR"\nexit {exit_code}\n'
                            )
                            environment = {
                                "PATH": os.defpath,
                                "WORK_DIR": str(caller),
                                "OUT_DIR": str(owned / "out"),
                                "FOXHOLE_DNS_ROOT": str(owned),
                                "TMPDIR": str(owned),
                                "KEEP_WORK_DIR": keep,
                            }
                            result = subprocess.run(
                                ["/bin/bash", str(script)], env=environment,
                                capture_output=True, text=True, check=False, timeout=10,
                            )
                            self.assertEqual(exit_code, result.returncode, result.stderr)
                            self.assertTrue(caller.is_dir())
                            self.assertEqual("owned fixture sentinel\n", sentinel.read_text())
                            child = Path(result.stdout.strip())
                            self.assertEqual(caller, child.parent)
                            self.assertTrue(child.name.startswith("foxhole-db-work."))
                            self.assertEqual(keep == "true", child.exists())


def converter_namespace():
    source = (ROOT / "build-threat-intel.sh").read_text()
    body = source.split("<<'PYTHON'\n", 1)[1].split("\nPYTHON", 1)[0]
    selected = []
    for node in ast.parse(body).body:
        if isinstance(node, ast.Import):
            names = [entry for entry in node.names if entry.name in {"re", "ipaddress"}]
            if names:
                selected.append(ast.Import(names=names))
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name)
            and target.id in {"DOMAIN_RE", "IPV4_RE", "IPV6_RE", "stats", "domains", "ips"}
            for target in node.targets
        ):
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in {"add_ip", "add_domain", "note_skip"}:
            selected.append(node)
    namespace = {}
    module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    exec(compile(module, str(ROOT / "build-threat-intel.sh"), "exec"), namespace)
    return namespace


class ConverterNumericTests(unittest.TestCase):
    def test_semantic_ip_values_and_domain_controls(self):
        cases = (
            ("ip", "2001:0DB8:0000:0000:0000:0000:0000:0001", {"2001:db8::1"}),
            ("ip", "2001:db8::1", {"2001:db8::1"}),
            ("ip", "::::", set()),
            ("ip", "1:2:3:4:5:6:7:8:9", set()),
            ("ip", "::ffff:192.0.2.1", {ipaddress.ip_address("::ffff:192.0.2.1").compressed}),
            ("ip", "198.51.100.7", {"198.51.100.7"}),
            ("ip", "256.51.100.7", set()),
            ("ip", "019.51.100.7", set()),
            ("ip", "owned.example", set()),
            ("domain", "https://OWNED.Example/path", {"owned.example"}),
            ("domain", "*.OWNED.example", {"owned.example"}),
            ("domain", "example", set()),
        )
        namespace = converter_namespace()
        for kind, value, expected in cases:
            with self.subTest(kind=kind, value=value):
                namespace["ips"].clear()
                namespace["domains"].clear()
                namespace["add_ip" if kind == "ip" else "add_domain"](value, "owned fixture")
                self.assertEqual(expected, set(namespace["ips" if kind == "ip" else "domains"]))


class PublicationTimestampSafetyTests(unittest.TestCase):
    def run_feed(self, overrides, root, schema=1):
        source = (ROOT / "verify-feeds.sh").read_text()
        begin = source.index("manifest_epoch() {") if "manifest_epoch() {" in source else source.index("manifest_age() {")
        body = source[begin:source.index("\nprintf 'Verifying")]
        artifact = b"owned artifact\n"
        (root / "rules.bin").write_bytes(artifact)
        document = {'schema': schema, 'format': 'owned-format', 'name': 'owned-feed',
                    'generated_at_unix': 1699999999, 'expires_at_unix': 1700000100,
                    'artifact': {'file': 'rules.bin', 'size': len(artifact),
                                 'sha256': hashlib.sha256(artifact).hexdigest()}, **overrides}
        (root / "owned-manifest.json").write_text(json.dumps(document))
        setup = 'DIR="$1"\nVERIFY_SIGNATURES=false\nnow_unix=1700000000\nmax_age_seconds=3888000\nFAILURES=0\n'
        setup += 'fail() { FAILURES=$((FAILURES + 1)); }\npass() { :; }\n'
        call = f'''
check_feed owned owned-manifest.json {schema} owned-format owned-feed \
  '.artifact | [.file, (.size|tostring), .sha256] | @tsv' rules.bin
test "$FAILURES" -eq 0
'''
        return subprocess.run(["bash", "-c", setup + body + call, "check", str(root)],
                              capture_output=True, text=True, check=False, timeout=10)

    def run_age(self, value, root):
        source = (ROOT / "verify-feeds.sh").read_text()
        begin = source.index("manifest_epoch() {") if "manifest_epoch() {" in source else source.index("manifest_age() {")
        body = source[begin:source.index("\ncheck_feed() {")]
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps(value))
        return subprocess.run(["bash", "-c", 'now_unix=1700000000\n' + body + '\nmanifest_age "$1"',
                               "check", str(manifest)], capture_output=True, text=True, check=False, timeout=10)

    def test_epoch_string_never_runs_shell_arithmetic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "arithmetic-evaluated"
            value = {'generated_at_unix': 'a[$(printf evaluated > ' + str(marker) + ')]'}
            result = self.run_age(value, root)
            self.assertFalse(marker.exists())
            self.assertNotEqual(0, result.returncode)

    def test_invalid_epoch_values_are_refused_and_valid_formats_keep_their_age(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for value in [True, False, -1, 1.25, 2**64, "1700000000"]:
                with self.subTest(value=value):
                    self.assertNotEqual(0, self.run_age({'generated_at_unix': value}, root).returncode)
            for document in [{'generated_at_unix': 1699999999}, {'generated_at': '2023-11-14T22:13:19Z'}]:
                result = self.run_age(document, root)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual('1', result.stdout.strip())

    def test_expiry_string_never_runs_shell_arithmetic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "expiry-evaluated"
            result = self.run_feed({'expires_at_unix': 'a[$(printf evaluated > ' + str(marker) + ')]'}, root)
            self.assertFalse(marker.exists())
            self.assertNotEqual(0, result.returncode)

    def test_future_generation_is_refused_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertNotEqual(0, self.run_feed({'generated_at_unix': 1700086401}, root).returncode)
            self.assertEqual(0, self.run_feed({}, root).returncode)

    def test_legacy_dns_future_generation_matches_client_ten_minute_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for skew, expected in ((600, 0), (601, 1)):
                with self.subTest(skew=skew):
                    result = self.run_feed({'generated_at_unix': 1700000000 + skew,
                                            'expires_at_unix': 1700000101 + skew}, root, schema=2)
                    self.assertEqual(expected, result.returncode)

    def test_legacy_dns_validity_matches_client_one_second_to_thirty_one_days(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for lifetime, expected in ((0, 1), (1, 0), (31 * 86400, 0), (31 * 86400 + 1, 1)):
                with self.subTest(lifetime=lifetime):
                    result = self.run_feed({'generated_at_unix': 1700000100,
                                            'expires_at_unix': 1700000100 + lifetime}, root, schema=2)
                    self.assertEqual(expected, result.returncode)


if __name__ == "__main__":
    unittest.main()
