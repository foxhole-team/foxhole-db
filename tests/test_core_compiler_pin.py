"""Synthetic pin/fallback contracts; no real compiler, keys, network or Git."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('compiler_pin', ROOT/'verify-core-compiler.py')
PIN = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(PIN)


class CoreCompilerPinTests(unittest.TestCase):
    def fixture(self):
        pin = {'schema': 1, 'sourceCommit': 'a'*40, 'producerCommit': 'b'*40,
               'handoffCommit': 'c'*40, 'handoffSha256': 'd'*64,
               'archiveSha256': 'e'*64, 'archiveBytes': 123, 'compilerSha256': 'f'*64}
        handoff = {'source_commit': pin['sourceCommit'], 'producer_commit': pin['producerCommit'],
                   'archive_sha256': pin['archiveSha256'], 'archive_bytes': pin['archiveBytes'],
                   'files': {'compiler': {'sha256': pin['compilerSha256']}}}
        return pin, handoff

    def test_exact_synthetic_pin_is_accepted(self):
        pin, handoff = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'pin.json';path.write_text(json.dumps(pin))
            self.assertEqual(pin, PIN.pin_document(path))
        PIN.bind_pin(pin, handoff, 'compiler')

    def test_wrong_source_producer_or_hash_is_rejected(self):
        pin, handoff = self.fixture()
        for key in ('source_commit', 'producer_commit', 'archive_sha256', 'archive_bytes'):
            bad = copy.deepcopy(handoff);bad[key] = 999 if key == 'archive_bytes' else '0'*len(bad[key])
            with self.subTest(key=key), self.assertRaises(ValueError):
                PIN.bind_pin(pin, bad, 'compiler')
        bad = copy.deepcopy(handoff);bad['files']['compiler']['sha256'] = '0'*64
        with self.assertRaises(ValueError):
            PIN.bind_pin(pin, bad, 'compiler')

    def test_missing_compiler_or_unbound_pin_is_rejected(self):
        pin, handoff = self.fixture();handoff['files'].clear()
        with self.assertRaises(ValueError):
            PIN.bind_pin(pin, handoff, 'compiler')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'pin.json';pin['sourceCommit'] = None;path.write_text(json.dumps(pin))
            with self.assertRaises(ValueError):
                PIN.pin_document(path)

    def test_github_prebuilt_requirement_never_falls_back_to_cargo(self):
        source = (ROOT/'build-adguard-dns-filter.sh').read_text()
        function = source[source.index('resolve_compiler() {'):source.index('\nresolve_compiler\n')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);marker = root/'cargo-called';cargo = root/'cargo'
            cargo.write_text('#!/bin/sh\ntouch "$CARGO_MARKER"\n');cargo.chmod(0o700)
            env = {**os.environ, 'FOXHOLE_DNS_REQUIRE_PREBUILT': 'true',
                   'FOXCORE_DNS_COMPILE_BIN': str(root/'missing'), 'FOXCORE_ROOT': str(root),
                   'CARGO_BIN': str(cargo), 'CARGO_MARKER': str(marker)}
            result = subprocess.run(['/bin/bash', '-c', 'set -eu\nneed() { :; }\n' + function + '\nresolve_compiler\n'], env=env, capture_output=True, text=True, timeout=3)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Pinned prebuilt', result.stderr)
            self.assertFalse(marker.exists())

    def test_required_prebuilt_rejects_relative_path_name_and_symlink(self):
        source = (ROOT/'build-adguard-dns-filter.sh').read_text()
        function = source[source.index('resolve_compiler() {'):source.index('\nresolve_compiler\n')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);compiler = root/'compiler';compiler.write_text('#!/bin/sh\nexit 0\n');compiler.chmod(0o700)
            link = root/'compiler-link';link.symlink_to(compiler)
            for selected in ('compiler', './compiler', str(link)):
                env = {**os.environ, 'FOXHOLE_DNS_REQUIRE_PREBUILT': 'true', 'FOXCORE_DNS_COMPILE_BIN': selected}
                result = subprocess.run(['/bin/bash', '-c', 'set -eu\nneed() { :; }\n' + function + '\nresolve_compiler\n'], cwd=root, env=env, capture_output=True, text=True, timeout=3)
                with self.subTest(selected=selected):
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn('absolute regular nonlink executable', result.stderr)
            env['FOXCORE_DNS_COMPILE_BIN'] = str(compiler)
            result = subprocess.run(['/bin/bash', '-c', 'set -eu\nneed() { :; }\n' + function + '\nresolve_compiler\n'], cwd=root, env=env, capture_output=True, text=True, timeout=3)
            self.assertEqual(0, result.returncode)


if __name__ == '__main__':
    unittest.main()
