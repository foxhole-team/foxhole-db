import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('delivery', ROOT / 'verify-dns-categories.py')
DELIVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELIVERY)


class DnsCategoryDeliveryTest(unittest.TestCase):
    def setup_inputs(self, root):
        source_root = root / 'sources'
        spec_dir = root / 'specs'
        spec_dir.mkdir()
        sources = []
        for category in DELIVERY.converter.CATEGORIES:
            id = 'owned-' + category
            directory = source_root / id
            directory.mkdir(parents=True)
            data = f'||{category}.owned.invalid^\n||shared.owned.invalid^\n'.encode()
            (directory / 'filter.txt').write_bytes(data)
            sources.append({'id': id, 'repo': 'https://example.invalid/owned', 'commit': 'a' * 40,
                            'license': 'CC0-1.0', 'inputs': [{'path': 'filter.txt', 'sha256': hashlib.sha256(data).hexdigest()}],
                            'categories': [category], 'format': 'adblock-suffix'})
        for trackers in ['normal', 'pro']:
            for malicious in ['medium', 'full']:
                value = {'schema': 1, 'tiers': {'trackers': trackers, 'malicious': malicious},
                         'sources': sources, 'allow_suffixes': []}
                (spec_dir / f'{trackers}-{malicious}.json').write_text(json.dumps(value))
        now = int(time.time())
        (root / 'dns-category-source-pins.json').write_text(json.dumps({
            'schema': 1, 'reviewed_at_unix': now,
            'sources': [{'repo': 'https://example.invalid/owned', 'commit': 'a' * 40,
                         'committed_at_unix': now, 'api_url': 'https://example.invalid/owned/commit/' + 'a' * 40}],
        }))
        private = root / 'owned.private.pem'
        public = root / 'owned.public.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-out', str(private)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['openssl', 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        parent = root / 'caller-parent'
        parent.mkdir()
        sentinel = parent / 'sentinel'
        sentinel.write_bytes(b'caller-owned')
        env = {**os.environ, 'FOXCORE_DNS_COMPILE_BIN': os.environ.get('FOXCORE_DNS_COMPILE_BIN', '/missing-compiler'),
               'FOXHOLE_DNS_CATEGORY_SPEC_DIR': str(spec_dir), 'FOXHOLE_DNS_CATEGORY_SOURCE_ROOT': str(source_root),
               'FOXHOLE_DNS_PUBLIC_KEY': str(public), 'FOXHOLE_DNS_SIGNING_KEY': str(private),
               'FOXHOLE_DNS_REQUIRE_SIGNATURE': 'true', 'OUT_DIR': str(root / 'out'), 'WORK_DIR': str(parent),
               'SEQUENCE': str(2**64 - 1)}
        env.pop('FOXHOLE_DNS_SIGNING_KEY_PEM', None)
        return env, sentinel, public

    @unittest.skipUnless(os.environ.get("FOXCORE_DNS_COMPILE_BIN"), "actual compiler gate runs after source-built compiler")
    def test_actual_compiler_and_signed_four_variants_preserve_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env, sentinel, public = self.setup_inputs(root)
            subprocess.run(['bash', str(ROOT / 'build-dns-categories.sh')], env=env, check=True)
            self.assertEqual(b'caller-owned', sentinel.read_bytes())
            self.assertTrue(Path(env['FOXHOLE_DNS_SIGNING_KEY']).is_file())
            self.assertEqual(['sentinel'], sorted(p.name for p in sentinel.parent.iterdir()))
            for variant in ['normal-medium', 'normal-full', 'pro-medium', 'pro-full']:
                directory = root / 'out' / 'dns-categories' / variant
                subprocess.run(['python3', str(ROOT / 'verify-dns-categories.py'), str(directory),
                                '--public-key', str(public)], check=True)
                manifest = json.loads((directory / 'manifest.json').read_text())
                self.assertEqual(2**64 - 1, manifest['sequence'])
                self.assertEqual(5, manifest['artifact']['block_entries'])
                self.assertEqual({name: 2 for name in DELIVERY.converter.CATEGORIES}, manifest['artifact']['category_entries'])
                self.assertEqual(0, manifest['artifact']['allow_entries'])

    def test_compiler_failure_has_no_partial_delivery_and_preserves_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env, sentinel, _ = self.setup_inputs(root)
            compiler = root / 'fail-compiler.sh'
            compiler.write_text('#!/bin/sh\nexit 7\n')
            compiler.chmod(0o700)
            env['FOXCORE_DNS_COMPILE_BIN'] = str(compiler)
            result = subprocess.run(['bash', str(ROOT / 'build-dns-categories.sh')], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual(b'caller-owned', sentinel.read_bytes())
            self.assertEqual(['sentinel'], sorted(p.name for p in sentinel.parent.iterdir()))
            self.assertFalse((root / 'out').exists())

    @unittest.skipUnless(os.environ.get("FOXCORE_DNS_COMPILE_BIN"), "actual compiler gate runs after source-built compiler")
    def test_pem_environment_signs_all_variants_without_retaining_key_in_kept_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env, sentinel, public = self.setup_inputs(root)
            private = Path(env.pop('FOXHOLE_DNS_SIGNING_KEY'))
            env['FOXHOLE_DNS_SIGNING_KEY_PEM'] = private.read_text()
            env['KEEP_WORK_DIR'] = 'true'
            result = subprocess.run(['bash', str(ROOT / 'build-dns-categories.sh')], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn(env['FOXHOLE_DNS_SIGNING_KEY_PEM'], result.stdout + result.stderr)
            self.assertEqual(b'caller-owned', sentinel.read_bytes())
            self.assertEqual([], list(sentinel.parent.rglob('*.private.pem')))
            for variant in ['normal-medium', 'normal-full', 'pro-medium', 'pro-full']:
                subprocess.run(['python3', str(ROOT / 'verify-dns-categories.py'),
                                str(root / 'out' / 'dns-categories' / variant),
                                '--public-key', str(public)], check=True, capture_output=True)

    @unittest.skipUnless(os.environ.get("FOXCORE_DNS_COMPILE_BIN"), "actual compiler gate runs after source-built compiler")
    def test_mismatched_pem_key_fails_without_delivery_or_temporary_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env, sentinel, _ = self.setup_inputs(root)
            wrong_key = root / 'wrong.private.pem'
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-out', str(wrong_key)],
                           check=True, capture_output=True)
            env.pop('FOXHOLE_DNS_SIGNING_KEY')
            env['FOXHOLE_DNS_SIGNING_KEY_PEM'] = wrong_key.read_text()
            result = subprocess.run(['bash', str(ROOT / 'build-dns-categories.sh')], env=env,
                                    capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn(env['FOXHOLE_DNS_SIGNING_KEY_PEM'], result.stdout + result.stderr)
            self.assertEqual(b'caller-owned', sentinel.read_bytes())
            self.assertEqual(['sentinel'], sorted(p.name for p in sentinel.parent.iterdir()))
            self.assertFalse((root / 'out').exists())

    def test_exact_unsigned_bounds_never_accept_bool_float_or_wrap(self):
        for value in [True, 1.0, -1, 2**64]:
            with self.assertRaises(ValueError):
                DELIVERY.producer.checked_u64(value, 'sequence', positive=True)
        self.assertEqual(2**64 - 1, DELIVERY.producer.checked_u64(2**64 - 1, 'sequence'))

    def test_streamed_small_input_matches_whole_canonical_encoding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.setup_inputs(root)
            spec = DELIVERY.converter.strict_json((root / 'specs' / 'normal-medium.json').read_text())
            data, _ = DELIVERY.converter.build_tagged(spec, root / 'sources')
            self.assertEqual(data, DELIVERY.converter.canonical(json.loads(data)))


if __name__ == '__main__':
    unittest.main()
