import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_retry", ROOT / "publish-feed-release.py")
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class ReleaseRetryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.asset = Path(temporary.name) / "feed.bin"
        self.asset.write_bytes(b"signed feed")
        self.source = "a" * 40
        self.release = {
            "target_commitish": self.source, "tag_name": "data-feeds-123",
            "draft": False, "prerelease": False,
            "assets": [{"name": self.asset.name, "state": "uploaded", "size": 11,
                        "digest": "sha256:" + hashlib.sha256(b"signed feed").hexdigest()}],
        }

    def run_publish(self):
        return RELEASE.publish("foxhole-team/foxhole-db", "data-feeds-123", self.source,
                               [self.asset], "DB feeds", self.asset, delay=0)

    def test_502_after_publish_is_reconciled_without_a_second_create(self):
        missing = RELEASE.NotFound()
        with patch.object(RELEASE, "read_release", side_effect=[missing, self.release]), \
             patch.object(RELEASE, "verify_tag"), \
             patch.object(RELEASE, "command", return_value=subprocess.CompletedProcess([], 1)) as command:
            self.run_publish()
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][:3], ["gh", "release", "create"])

    def test_502_before_creation_retries_the_create(self):
        with patch.object(RELEASE, "read_release", side_effect=[RELEASE.NotFound(), RELEASE.NotFound(), self.release]), \
             patch.object(RELEASE, "verify_tag"), \
             patch.object(RELEASE, "command", return_value=subprocess.CompletedProcess([], 1)) as command:
            self.run_publish()
        self.assertEqual(command.call_count, 2)

    def test_digest_conflict_never_edits_or_replaces_a_release(self):
        self.release["assets"][0]["digest"] = "sha256:" + "b" * 64
        with patch.object(RELEASE, "read_release", return_value=self.release), \
             patch.object(RELEASE, "verify_tag"), patch.object(RELEASE, "command") as command:
            with self.assertRaisesRegex(ValueError, "asset mismatch"):
                self.run_publish()
        command.assert_not_called()

    def test_other_source_or_incomplete_release_is_rejected(self):
        for field, value in [("target_commitish", "b" * 40), ("assets", [])]:
            with self.subTest(field=field), \
                 patch.object(RELEASE, "read_release", return_value=dict(self.release, **{field: value})), \
                 patch.object(RELEASE, "verify_tag"), patch.object(RELEASE, "command") as command:
                with self.assertRaises(ValueError):
                    self.run_publish()
                command.assert_not_called()

    def test_complete_draft_is_published_then_read_back(self):
        with patch.object(RELEASE, "read_release", side_effect=[dict(self.release, draft=True), self.release]), \
             patch.object(RELEASE, "verify_tag"), \
             patch.object(RELEASE, "command", return_value=subprocess.CompletedProcess([], 0)) as command:
            self.run_publish()
        self.assertEqual(command.call_args.args[0][:3], ["gh", "release", "edit"])

    def test_retry_exhaustion_is_a_failure(self):
        with patch.object(RELEASE, "read_release", side_effect=RELEASE.NotFound()), \
             patch.object(RELEASE, "command", return_value=subprocess.CompletedProcess([], 1)) as command:
            with self.assertRaisesRegex(RuntimeError, "not confirmed"):
                self.run_publish()
        self.assertEqual(command.call_count, 3)

    def test_readback_retries_server_errors_but_not_permission_errors(self):
        for code, count in [(502, 3), (403, 1)]:
            with self.subTest(code=code), patch.object(RELEASE.time, "sleep"), \
                 patch.object(RELEASE.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", f"HTTP {code}")) as run:
                with self.assertRaises(RuntimeError):
                    RELEASE.api("repos/foxhole-team/foxhole-db/releases/tags/data-feeds-123")
                self.assertEqual(run.call_count, count)

    def test_tag_must_resolve_to_expected_source(self):
        for obj in [{"type": "commit", "sha": "b" * 40}, {"type": "tag", "sha": self.source}]:
            with self.subTest(obj=obj), patch.object(RELEASE, "api", return_value={"object": obj}):
                with self.assertRaises(ValueError):
                    RELEASE.verify_tag("foxhole-team/foxhole-db", "data-feeds-123", self.source)

    def test_pages_upload_and_deploy_select_the_current_attempt(self):
        workflow = (ROOT / ".github/workflows/feeds.yml").read_text()
        name = "github-pages-${{ github.run_id }}-${{ github.run_attempt }}"
        self.assertIn("name: " + name, workflow)
        self.assertIn("artifact_name: " + name, workflow)
        artifacts = [name.replace("${{ github.run_id }}", "123").replace("${{ github.run_attempt }}", str(attempt))
                     for attempt in (1, 2)]
        self.assertEqual(artifacts.count("github-pages-123-2"), 1)


if __name__ == "__main__":
    unittest.main()
