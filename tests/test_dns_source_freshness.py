import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FETCH = load("source_fetch", "fetch-dns-category-sources.py")
PRODUCER = load("source_producer", "dns-categories-manifest.py")
NOW = 1793318400


class DnsSourceFreshnessTest(unittest.TestCase):
    def inputs(self, root, age=0):
        specs = root / "specs"
        specs.mkdir()
        directory = root / "sources" / "owned"
        directory.mkdir(parents=True)
        raw = b"||ads.test^\n"
        (directory / "list.txt").write_bytes(raw)
        source = {
            "id": "owned", "repo": "https://github.com/AdguardTeam/AdguardFilters",
            "commit": "a" * 40, "license": "CC0-1.0", "format": "adblock-suffix",
            "categories": ["ads"],
            "inputs": [{"path": "list.txt", "sha256": hashlib.sha256(raw).hexdigest()}],
        }
        specification = {"schema": 1, "tiers": {"trackers": "normal", "malicious": "medium"},
                         "sources": [source], "allow_suffixes": []}
        spec_path = specs / "normal-medium.json"
        spec_path.write_text(json.dumps(specification))
        review = {
            "schema": 1, "reviewed_at_unix": NOW,
            "sources": [{"repo": source["repo"], "commit": source["commit"],
                         "committed_at_unix": NOW - age,
                         "api_url": "https://api.github.com/repos/AdguardTeam/AdguardFilters/commits/" + "a" * 40}],
        }
        review_path = root / "dns-category-source-pins.json"
        review_path.write_text(json.dumps(review))
        return specs, root / "sources", spec_path, review_path, review

    def test_stale_pin_is_refused_even_when_cached_hash_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            specs, sources, *_ = self.inputs(Path(temporary), age=7 * 86400 + 1)
            with patch("time.time", return_value=NOW):
                with self.assertRaisesRegex(ValueError, "source pin age"):
                    FETCH.fetch_specs(specs, sources)

    def test_missing_review_is_unknown_not_fresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            specs, sources, _, review, _ = self.inputs(Path(temporary))
            review.unlink()
            with patch("time.time", return_value=NOW):
                with self.assertRaisesRegex(ValueError, "source pin review"):
                    FETCH.fetch_specs(specs, sources)

    def test_exact_age_boundary_uses_cached_immutable_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            specs, sources, *_ = self.inputs(Path(temporary), age=7 * 86400)
            with patch("time.time", return_value=NOW):
                FETCH.fetch_specs(specs, sources)
            self.assertEqual(b"||ads.test^\n", (sources / "owned/list.txt").read_bytes())

    def test_future_commit_or_review_timestamp_is_refused(self):
        for field in ["committed_at_unix", "reviewed_at_unix"]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                specs, sources, _, path, review = self.inputs(Path(temporary))
                if field == "committed_at_unix":
                    review["sources"][0][field] = NOW + 301
                else:
                    review[field] = NOW + 301
                path.write_text(json.dumps(review))
                with patch("time.time", return_value=NOW):
                    with self.assertRaisesRegex(ValueError, "future"):
                        FETCH.fetch_specs(specs, sources)

    def test_review_must_bind_exact_repo_and_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            specs, sources, _, path, review = self.inputs(Path(temporary))
            review["sources"][0]["commit"] = "b" * 40
            review["sources"][0]["api_url"] = "https://api.github.com/repos/AdguardTeam/AdguardFilters/commits/" + "b" * 40
            path.write_text(json.dumps(review))
            with patch("time.time", return_value=NOW):
                with self.assertRaisesRegex(ValueError, "unreviewed source pin"):
                    FETCH.fetch_specs(specs, sources)

    def test_review_api_reference_must_name_the_same_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            specs, sources, _, path, review = self.inputs(Path(temporary))
            review["sources"][0]["api_url"] = "https://api.github.com/repos/AdguardTeam/AdguardFilters/commits/" + "b" * 40
            path.write_text(json.dumps(review))
            with patch("time.time", return_value=NOW):
                with self.assertRaisesRegex(ValueError, "API reference"):
                    FETCH.fetch_specs(specs, sources)

    def test_bool_timestamp_is_not_an_epoch(self):
        with tempfile.TemporaryDirectory() as temporary:
            specs, sources, _, path, review = self.inputs(Path(temporary))
            review["sources"][0]["committed_at_unix"] = True
            path.write_text(json.dumps(review))
            with patch("time.time", return_value=NOW):
                with self.assertRaisesRegex(ValueError, "timestamp"):
                    FETCH.fetch_specs(specs, sources)

    def test_supplied_source_root_cannot_bypass_producer_age_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, sources, spec, _, _ = self.inputs(root, age=7 * 86400 + 1)
            with patch("time.time", return_value=NOW):
                try:
                    PRODUCER.build_variant(spec, sources, Path("/usr/bin/false"), root / "out",
                                           "a" * 64, 1, 1, 2)
                except ValueError as error:
                    self.assertIn("source pin age", str(error))
                except subprocess.CalledProcessError:
                    self.fail("stale source reached the compiler")
                else:
                    self.fail("stale source was accepted")
            self.assertFalse((root / "out").exists())


if __name__ == "__main__":
    unittest.main()
