import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NOW = 1794247200
COMMIT = "b" * 40
REPO = "https://github.com/AdguardTeam/AdguardFilters"
API = "https://api.github.com/repos/AdguardTeam/AdguardFilters/commits/"
RAW = "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/"


class DnsSourceRefreshTest(unittest.TestCase):
    def setUp(self):
        filename = ROOT / "refresh-dns-category-sources.py"
        self.assertTrue(filename.is_file(), "automatic immutable source snapshot is missing")
        spec = importlib.util.spec_from_file_location("refresh", filename)
        self.refresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.refresh)

    def inputs(self, root):
        specs = root / "committed-specs"
        specs.mkdir()
        source = {"id": "adguard-ads", "repo": REPO, "commit": "a" * 40,
                  "license": "GPL-3.0", "categories": ["ads"], "format": "adblock-suffix",
                  "inputs": [{"path": "BaseFilter/sections/adservers.txt", "sha256": "0" * 64}]}
        for trackers in ["normal", "pro"]:
            for malicious in ["medium", "full"]:
                (specs / f"{trackers}-{malicious}.json").write_text(json.dumps({
                    "schema": 1, "tiers": {"trackers": trackers, "malicious": malicious},
                    "sources": [source], "allow_suffixes": [],
                }))
        head = {"sha": COMMIT, "commit": {"committer": {"date": "2026-11-09T17:41:12Z"}},
                "url": API + COMMIT,
                "html_url": REPO + "/commit/" + COMMIT}
        data = b"||ads.owned.invalid^\n"
        responses = {API.rstrip("/") + "?per_page=1": json.dumps([head]).encode(),
                     API + COMMIT: json.dumps(head).encode(),
                     RAW + COMMIT + "/BaseFilter/sections/adservers.txt": data}
        return specs, responses, data

    def fetch(self, responses):
        def download(url, limit):
            return responses[url]
        return download

    def test_fresh_official_head_builds_complete_immutable_snapshot_without_editing_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specs, responses, data = self.inputs(root)
            before = {p.name: p.read_bytes() for p in specs.iterdir()}
            output = root / "snapshot"
            self.refresh.refresh_sources(specs, output, fetch=self.fetch(responses), now=NOW)
            self.assertEqual(before, {p.name: p.read_bytes() for p in specs.iterdir()})
            for name in before:
                current = json.loads((output / "specs" / name).read_text())
                original = json.loads(before[name])
                self.assertEqual(original["tiers"], current["tiers"])
                self.assertEqual([], current["allow_suffixes"])
                source = current["sources"][0]
                self.assertEqual(COMMIT, source["commit"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), source["inputs"][0]["sha256"])
                self.assertEqual(["ads"], source["categories"])
                self.assertEqual(data, (output / "sources/adguard-ads/BaseFilter/sections/adservers.txt").read_bytes())
            audit = json.loads((output / "audit.json").read_text())
            self.assertEqual("automatic_validation", audit["validation"])
            self.assertEqual(NOW, audit["observed_at_unix"])
            self.assertEqual(1, audit["sources"][0]["supported_suffixes"])
            self.assertFalse(audit["human_review_claimed"])
            review = json.loads((output / "dns-category-source-pins.json").read_text())
            self.assertEqual(COMMIT, review["sources"][0]["commit"])

    def test_stale_head_is_refused_instead_of_making_old_commit_fresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specs, responses, _ = self.inputs(root)
            for url in [API.rstrip("/") + "?per_page=1", API + COMMIT]:
                value = json.loads(responses[url]); head = value[0] if isinstance(value, list) else value
                head["commit"]["committer"]["date"] = "2026-10-30T00:00:00Z"
                responses[url] = json.dumps(value).encode()
            with self.assertRaisesRegex(ValueError, "source pin age"):
                self.refresh.refresh_sources(specs, root / "snapshot", fetch=self.fetch(responses), now=NOW)
            self.assertFalse((root / "snapshot").exists())

    def test_exact_commit_response_must_bind_head_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specs, responses, _ = self.inputs(root)
            exact = json.loads(responses[API + COMMIT]); exact["sha"] = "c" * 40
            responses[API + COMMIT] = json.dumps(exact).encode()
            with self.assertRaisesRegex(ValueError, "commit identity"):
                self.refresh.refresh_sources(specs, root / "snapshot", fetch=self.fetch(responses), now=NOW)
            self.assertFalse((root / "snapshot").exists())

    def test_unrepresentable_refreshed_exception_has_no_partial_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specs, responses, _ = self.inputs(root)
            responses[RAW + COMMIT + "/BaseFilter/sections/adservers.txt"] = b"||parent.test^\n@@||safe.parent.test^\n"
            with self.assertRaisesRegex(ValueError, "not representable"):
                self.refresh.refresh_sources(specs, root / "snapshot", fetch=self.fetch(responses), now=NOW)
            self.assertFalse((root / "snapshot").exists())
            self.assertEqual(["committed-specs"], sorted(p.name for p in root.iterdir()))

    def test_existing_snapshot_is_preserved_on_new_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specs, responses, _ = self.inputs(root)
            output = root / "snapshot"; output.mkdir(); (output / "previous-good").write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                self.refresh.refresh_sources(specs, output, fetch=self.fetch(responses), now=NOW)
            self.assertEqual(b"keep", (output / "previous-good").read_bytes())

    def test_unknown_repository_or_path_escape_is_refused(self):
        for change in ["repo", "path"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                specs, responses, _ = self.inputs(root)
                for file in specs.iterdir():
                    value = json.loads(file.read_text())
                    source = value["sources"][0]
                    if change == "repo": source["repo"] = "https://example.invalid/unreviewed"
                    else: source["inputs"][0]["path"] = "../../outside"
                    file.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    self.refresh.refresh_sources(specs, root / "snapshot", fetch=self.fetch(responses), now=NOW)
                self.assertFalse((root / "snapshot").exists())

    def test_download_bounds_are_checked_even_for_custom_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specs, responses, _ = self.inputs(root)
            self.refresh.MAX_INPUT_BYTES = 8
            with self.assertRaisesRegex(ValueError, "bounds"):
                self.refresh.refresh_sources(specs, root / "snapshot", fetch=self.fetch(responses), now=NOW)
            self.assertFalse((root / "snapshot").exists())

    def test_future_commit_and_different_exact_timestamp_are_refused(self):
        for changed in ["future", "mismatch"]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                specs, responses, _ = self.inputs(root)
                exact = json.loads(responses[API + COMMIT])
                exact["commit"]["committer"]["date"] = "2026-11-10T00:00:00Z"
                responses[API + COMMIT] = json.dumps(exact).encode()
                if changed == "future":
                    responses[API.rstrip("/") + "?per_page=1"] = json.dumps([exact]).encode()
                with self.assertRaisesRegex(ValueError, "future|timestamp mismatch"):
                    self.refresh.refresh_sources(specs, root / "snapshot", fetch=self.fetch(responses), now=NOW)
                self.assertFalse((root / "snapshot").exists())

    def test_duplicate_metadata_keys_and_wrong_canonical_api_identity_are_refused(self):
        for changed in ["duplicate", "url"]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                specs, responses, _ = self.inputs(root)
                if changed == "duplicate":
                    responses[API + COMMIT] = b'{"sha":"' + COMMIT.encode() + b'","sha":"different"}'
                else:
                    value = json.loads(responses[API + COMMIT]); value["url"] = "https://example.invalid/commit/" + COMMIT
                    responses[API + COMMIT] = json.dumps(value).encode()
                with self.assertRaisesRegex(ValueError, "duplicate|commit identity"):
                    self.refresh.refresh_sources(specs, root / "snapshot", fetch=self.fetch(responses), now=NOW)
                self.assertFalse((root / "snapshot").exists())

    def test_transport_failure_preserves_committed_sources_and_caller_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            specs, responses, _ = self.inputs(root)
            before = {p.name: p.read_bytes() for p in specs.iterdir()}
            sentinel = root / "previous-signed-db"; sentinel.write_bytes(b"signed-good")
            def fail(url, limit):
                raise ConnectionError("owned transport failure")
            with self.assertRaises(ConnectionError):
                self.refresh.refresh_sources(specs, root / "snapshot", fetch=fail, now=NOW)
            self.assertEqual(before, {p.name: p.read_bytes() for p in specs.iterdir()})
            self.assertEqual(b"signed-good", sentinel.read_bytes())
            self.assertFalse((root / "snapshot").exists())


if __name__ == "__main__":
    unittest.main()
