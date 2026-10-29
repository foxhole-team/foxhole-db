import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LegacyDnsSourcePolicyTest(unittest.TestCase):
    def source_ref(self, overrides):
        text = (ROOT / 'build-adguard-dns-filter.sh').read_text()
        prologue = text[:text.index('trap cleanup EXIT') + len('trap cleanup EXIT')]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / 'owned.sh'
            script.write_text(prologue + '\nprintf "%s\\n" "$SOURCE_REF"\n')
            env = {'PATH': os.defpath, 'FOXHOLE_DNS_ROOT': str(root), 'WORK_DIR': str(root / 'caller'), **overrides}
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True, check=True)
            return result.stdout.strip()

    def test_default_uses_official_tracked_generated_input_branch(self):
        self.assertEqual('gh-pages', self.source_ref({}))

    def test_explicit_legacy_reference_is_preserved(self):
        self.assertEqual('HEAD', self.source_ref({'SOURCE_REF': 'HEAD'}))

    def test_adguard_specific_reference_has_existing_priority(self):
        self.assertEqual('owned-commit', self.source_ref({'SOURCE_REF': 'HEAD', 'ADGUARD_SOURCE_REF': 'owned-commit'}))


if __name__ == '__main__':
    unittest.main()
