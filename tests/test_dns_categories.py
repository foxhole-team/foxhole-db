import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("dns_categories", ROOT / "build-dns-categories.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class DnsCategoryGeneratorTest(unittest.TestCase):
    def source(self, root, name, text, category, format_name="adblock-suffix"):
        (root / name).mkdir(exist_ok=True)
        path = root / name / (name + ".txt")
        path.write_text(text)
        return {
            "id": name, "repo": "https://example.invalid/owned", "commit": "a" * 40,
            "license": "CC0-1.0", "inputs": [{"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}],
            "categories": [category], "format": format_name,
        }

    def specification(self, sources):
        return {"schema": 1, "tiers": {"trackers": "normal", "malicious": "medium"}, "sources": sources, "allow_suffixes": []}

    def test_source_exception_does_not_override_other_category(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ads = self.source(root, "ads", "||shared.owned.invalid^\n@@||shared.owned.invalid^\n||ads.owned.invalid^\n", "ads")
            telemetry = self.source(root, "telemetry", "shared.owned.invalid\n", "telemetry", "domain-suffix")
            data, _ = BUILDER.build_tagged(self.specification([ads, telemetry]), root)
            document = json.loads(data)
            shared = next(row for row in document["block"] if row["domain"] == "shared.owned.invalid")
            self.assertEqual(["telemetry"], shared["categories"])
            self.assertEqual([], document["allow_suffixes"])

    def test_narrow_exception_under_blocked_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ads = self.source(root, "ads", "||parent.test^\n@@||safe.parent.test^\n", "ads")
            with self.assertRaisesRegex(ValueError, "source.*exception.*suffix"):
                BUILDER.build_tagged(self.specification([ads]), root)

    def test_unrepresentable_ads_exception_cannot_bypass_malicious(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ads = self.source(root, "ads", "||parent.test^\n@@||safe.parent.test^\n", "ads")
            malicious = self.source(root, "malicious", "safe.parent.test\n", "malicious", "domain-suffix")
            with self.assertRaisesRegex(ValueError, "source.*exception.*suffix"):
                BUILDER.build_tagged(self.specification([ads, malicious]), root)

    def test_whole_source_exception_keeps_independent_malicious_block(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ads = self.source(root, "ads", "||shared.test^\n@@||shared.test^\n||ads.test^\n", "ads")
            malicious = self.source(root, "malicious", "shared.test\n", "malicious", "domain-suffix")
            data, _ = BUILDER.build_tagged(self.specification([ads, malicious]), root)
            document = json.loads(data)
            self.assertEqual([], document["allow_suffixes"])
            self.assertEqual(["malicious"], next(row["categories"] for row in document["block"] if row["domain"] == "shared.test"))

    def test_source_exception_keeps_independent_same_category_block(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.source(root, "first", "||shared.test^\n@@||shared.test^\n||ads.test^\n", "ads")
            independent = self.source(root, "second", "shared.test\n", "ads", "domain-suffix")
            data, _ = BUILDER.build_tagged(self.specification([source, independent]), root)
            document = json.loads(data)
            self.assertEqual([], document["allow_suffixes"])
            self.assertEqual(["ads"], next(row["categories"] for row in document["block"] if row["domain"] == "shared.test"))

    def test_source_record_bounds_are_enforced_before_accumulation(self):
        with patch.object(BUILDER, "MAX_ENTRIES", 1):
            with self.assertRaisesRegex(ValueError, "entry limit"):
                BUILDER.convert_source(b"||one.test^\n||two.test^\n", "adblock-suffix")

    def test_global_allow_bounds_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.source(root, "ads", "||ads.test^\n", "ads")
            specification = self.specification([source])
            specification["allow_suffixes"] = ["first.test", "second.test"]
            with patch.object(BUILDER, "MAX_ENTRIES", 1):
                with self.assertRaisesRegex(ValueError, "allow.*limit"):
                    BUILDER.build_tagged(specification, root)

    def test_total_rule_bounds_include_independent_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self.source(root, "first", "||first.test^\n", "ads")
            second = self.source(root, "second", "||second.test^\n", "ads")
            with patch.object(BUILDER, "MAX_ENTRIES", 1):
                with self.assertRaisesRegex(ValueError, "entry limit"):
                    BUILDER.build_tagged(self.specification([first, second]), root)

    def test_source_file_bounds_and_unknown_format_are_refused(self):
        with patch.object(BUILDER, "MAX_INPUT_BYTES", 8):
            with self.assertRaisesRegex(ValueError, "file bounds"):
                BUILDER.convert_source(b"||ads.test^\n", "adblock-suffix")
        with self.assertRaisesRegex(ValueError, "unsupported source format"):
            BUILDER.convert_source(b"ads.test\n", "hosts")

    def test_overlapping_suffix_categories_union_and_canonicalize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ads = self.source(root, "ads", "||SHARED.owned.invalid^\n", "ads")
            telemetry = self.source(root, "telemetry", "shared.owned.invalid\n", "telemetry", "domain-suffix")
            data, _ = BUILDER.build_tagged(self.specification([telemetry, ads]), root)
            self.assertEqual(data, BUILDER.canonical(json.loads(data)))
            self.assertEqual(["telemetry", "ads"], json.loads(data)["block"][0]["categories"])
            self.assertTrue(data.endswith(b"\n") and not data.endswith(b"\n\n"))

    def test_digest_mismatch_and_escape_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.source(root, "ads", "||ads.owned.invalid^\n", "ads")
            source["inputs"][0]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                BUILDER.build_tagged(self.specification([source]), root)
            source["inputs"][0]["path"] = "../outside.txt"
            with self.assertRaises(ValueError):
                BUILDER.build_tagged(self.specification([source]), root)

    def test_unsupported_exact_regex_and_path_are_not_guessed(self):
        block, allow, skipped = BUILDER.convert_source(b"|https://ads.owned.invalid/path|\n/regexp/\n||ads.owned.invalid^\n", "adblock-suffix")
        self.assertEqual({"ads.owned.invalid"}, block)
        self.assertEqual(set(), allow)
        self.assertEqual(2, skipped)

    def test_duplicate_json_and_unknown_categories_are_refused(self):
        with self.assertRaises(ValueError):
            BUILDER.strict_json('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):
            BUILDER.categories(["ads", "ads"])
        with self.assertRaises(ValueError):
            BUILDER.categories(["unknown"])

    def test_ascii_quote_backslash_and_u64_golden_encoding(self):
        expected = b'{"escaped":"quote\\\"backslash\\\\","integer":18446744073709551615}\n'
        self.assertEqual(expected, BUILDER.canonical({"integer": 18446744073709551615, "escaped": 'quote"backslash\\'}))


if __name__ == "__main__":
    unittest.main()
