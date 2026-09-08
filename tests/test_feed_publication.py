import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publication", ROOT / "should-publish-feeds.py")
PUBLICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLICATION)
NOW = 1_788_000_000


class FeedPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate, self.published = self.root / "candidate", self.root / "published"
        for directory, age in [(self.candidate, 0), (self.published, PUBLICATION.DAY)]:
            directory.mkdir()
            for name in PUBLICATION.MANIFESTS:
                document = {
                    "schema": 1, "name": name, "generated_at_unix": NOW - age,
                    "artifact": {"file": "rules.bin", "size": 10, "sha256": "a" * 64},
                }
                if name == "manifest.json":
                    document["expires_at_unix"] = NOW + 29 * PUBLICATION.DAY
                self.write(directory / name, document)
            self.fingerprints(directory, str(NOW - age))
            for name in PUBLICATION.SOURCE_INFO:
                self.write(directory / name, {"generated_at": str(NOW - age), "source": {"revision": "one"}})

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def fingerprints(self, directory, timestamp, profiles=None):
        document = {"schema": 1, "generated_at": timestamp, "profiles": profiles or [{"name": "chrome", "table": [1, 2]}]}
        self.write(directory / "fingerprints.json", document)
        payload = (directory / "fingerprints.json").read_bytes()
        manifest = PUBLICATION.read_json(directory / "fingerprint-manifest.json")
        manifest["artifact"] = {"file": "fingerprints.json", "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        self.write(directory / "fingerprint-manifest.json", manifest)

    def reason(self):
        return PUBLICATION.publication_reason(self.candidate, self.published, NOW)

    def change(self, directory, name, mutate):
        value = PUBLICATION.read_json(directory / name)
        mutate(value)
        self.write(directory / name, value)

    def test_build_clocks_alone_do_not_publish(self):
        self.assertIsNone(self.reason())

    def test_changed_dns_bytes_publish(self):
        self.change(self.candidate, "manifest.json", lambda value: value["artifact"].update(sha256="b" * 64))
        self.assertIsNotNone(self.reason())

    def test_changed_fingerprint_table_or_profile_provenance_publishes(self):
        self.fingerprints(self.candidate, str(NOW), [{"name": "chrome", "table": [1, 3]}])
        self.assertIsNotNone(self.reason())

    def test_changed_source_revision_publishes_even_with_identical_artifact(self):
        self.change(self.candidate, "threat-intel-source-info.json", lambda value: value["source"].update(revision="two"))
        self.assertIsNotNone(self.reason())

    def test_approaching_dns_expiry_requires_publication(self):
        self.change(self.published, "manifest.json", lambda value: value.update(expires_at_unix=NOW + 7 * PUBLICATION.DAY))
        self.assertIsNotNone(self.reason())

    def test_unchanged_non_dns_feed_is_renewed_before_client_age_limit(self):
        self.change(self.published, "bridges-manifest.json", lambda value: value.update(generated_at_unix=NOW - 21 * PUBLICATION.DAY))
        self.assertIsNotNone(self.reason())

    def test_corrupt_fingerprint_bytes_cannot_suppress_publication(self):
        (self.published / "fingerprints.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            self.reason()

    def test_fingerprint_contract_change_is_not_hidden_by_equal_tables(self):
        self.change(self.candidate, "fingerprint-manifest.json", lambda value: value.update(schema=2))
        self.assertIsNotNone(self.reason())

    def test_only_valid_manifest_signatures_are_accepted(self):
        key, public, manifest = self.root / "key.pem", self.root / "public.pem", self.root / "manifest.json"
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)], check=True, capture_output=True)
        manifest.write_text('{"schema":1}')
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(manifest) + ".sig", str(manifest)], check=True, capture_output=True)
        PUBLICATION.verify_signature(manifest, public)
        manifest.write_text('{"schema":2}')
        with self.assertRaisesRegex(ValueError, "valid publication signature"):
            PUBLICATION.verify_signature(manifest, public)


if __name__ == "__main__":
    unittest.main()
