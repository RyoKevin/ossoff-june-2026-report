"""Regression tests use only the published, anonymous aggregate fixtures."""

import contextlib
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_evidence as verifier


@contextlib.contextmanager
def fixture():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT)
            if path.is_file() and not {".git", "__pycache__"}.intersection(relative.parts):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
        yield root


def change_json(root, filename, mutate):
    path = root / "evidence" / filename
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def refresh_hash(root, name):
    path = root / "SHA256SUMS.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    digest = hashlib.sha256((root / name).read_bytes()).hexdigest()
    path.write_text("\n".join(digest + "  " + name if line[66:] == name else line for line in lines) + "\n", encoding="utf-8")


class VerificationTests(unittest.TestCase):
    def test_published_statistics(self):
        checks, summary = verifier.verify_statistics(ROOT)
        self.assertGreater(checks, 0)
        # Independent published expectations also guard against using overlapping periods.
        self.assertIn("27-dollar shares: 1.101803%, 5.147128%, 5.362053%", summary)
        self.assertIn("Last two days: 3,311/5,276 = 62.76% of 27-dollar transactions", summary)
        self.assertIn("Last two days: 62,596/240,940 = 25.98% of all transactions", summary)
        self.assertIn("TX-FL repeat-rate gap: 0.01942 pp", summary)

    def test_published_checksums(self):
        self.assertGreaterEqual(verifier.verify_checksums(ROOT), 6)

    def test_cli_locates_repository_from_another_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            run = subprocess.run([sys.executable, str(ROOT / "scripts/verify_evidence.py")], cwd=directory, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("PASS SHA-256", run.stdout)
        self.assertIn("PASS Aggregate arithmetic and README", run.stdout)

    def test_changed_readme_percentage_fails_even_with_updated_hash(self):
        with fixture() as root:
            path = root / "README.md"
            path.write_bytes(path.read_bytes().replace(b"5.362%", b"5.363%", 1))
            refresh_hash(root, "README.md")
            verifier.verify_checksums(root)
            with self.assertRaisesRegex(verifier.VerificationError, "README period table"):
                verifier.verify_statistics(root)
            run = subprocess.run([sys.executable, str(ROOT / "scripts/verify_evidence.py"), "--root", str(root)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 1)
            self.assertIn("FAIL Aggregate arithmetic and README", run.stderr)

    def test_changed_repeated_multiplier_is_detected(self):
        with fixture() as root:
            path = root / "README.md"
            path.write_bytes(path.read_bytes().replace(b"4.87", b"4.88", 1))
            with self.assertRaisesRegex(verifier.VerificationError, "multiplier"):
                verifier.verify_statistics(root)

    def test_missing_core_claim_is_detected(self):
        with fixture() as root:
            path = root / "README.md"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace("最后两天产生", "最后两天记录"), encoding="utf-8")
            with self.assertRaisesRegex(verifier.VerificationError, "claim missing"):
                verifier.verify_statistics(root)

    def test_cached_json_percentage_is_recomputed(self):
        with fixture() as root:
            change_json(root, "national.json", lambda data: data["periods"]["June30"]["ossoff"].update(p27_pct=5.0))
            with self.assertRaisesRegex(verifier.VerificationError, "stored rate disagrees"):
                verifier.verify_statistics(root)

    def test_state_national_cross_foot(self):
        with fixture() as root:
            def mutate(data):
                row = data["ossoff_state_comparison"][0]["June30"]
                row["2700"] += 1
                row["p27_pct"] = 100 * row["2700"] / row["transactions"]
                row["p27_small_pct"] = 100 * row["2700"] / row["small_transactions"]
            change_json(root, "national.json", mutate)
            with self.assertRaisesRegex(verifier.VerificationError, "State/national cross-foot"):
                verifier.verify_statistics(root)

    def test_duplicate_state_cannot_replace_missing_state(self):
        with fixture() as root:
            def mutate(data):
                rows = data["ossoff_state_comparison"]
                rows[-1] = rows[0]
            change_json(root, "national.json", mutate)
            with self.assertRaisesRegex(verifier.VerificationError, "coverage"):
                verifier.verify_statistics(root)

    def test_history_category_total(self):
        with fixture() as root:
            change_json(root, "donor_history.json", lambda data: data["late_27"]["baseline"]["exclusive_history_categories"].update(no_prior_identified_earmark=1085))
            with self.assertRaisesRegex(verifier.VerificationError, "history categories sum"):
                verifier.verify_statistics(root)

    def test_missing_adjacent_window_is_detected(self):
        with fixture() as root:
            change_json(root, "state_comparison.json", lambda data: data["adjacent_windows"].pop())
            with self.assertRaisesRegex(verifier.VerificationError, "Three adjacent windows"):
                verifier.verify_statistics(root)

    def test_missing_zero_amount_category_is_supported(self):
        data = verifier.load_evidence(ROOT)["national"]
        self.assertTrue(any("2700" not in row[p] for row in data["ossoff_state_comparison"] for p in verifier.PERIODS))
        verifier.verify_statistics(ROOT)

    def test_zero_denominator_and_invalid_counts_fail(self):
        for numerator, denominator in ((0, 0), (2, 1), (-1, 5), (True, 5), (1.5, 5)):
            with self.subTest(numerator=numerator, denominator=denominator):
                with self.assertRaises(verifier.VerificationError):
                    verifier.percent(numerator, denominator)

    def test_modified_file_hash(self):
        with fixture() as root:
            with (root / "evidence/public_sources.json").open("ab") as stream:
                stream.write(b" ")
            with self.assertRaisesRegex(verifier.VerificationError, "SHA-256 evidence/public_sources.json"):
                verifier.verify_checksums(root)

    def test_missing_file_hash(self):
        with fixture() as root:
            (root / "evidence/public_sources.json").unlink()
            with self.assertRaises(OSError):
                verifier.verify_checksums(root)

    def test_checksum_manifest_requires_original_files(self):
        with fixture() as root:
            path = root / "SHA256SUMS.txt"
            path.write_text("\n".join(line for line in path.read_text().splitlines() if not line.endswith("README.md")) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(verifier.VerificationError, "omits README"):
                verifier.verify_checksums(root)

    def test_checksum_rejects_malformed_duplicate_and_unsafe_entries(self):
        for entry in ("not a checksum", "0" * 64 + "  ../outside.json", "0" * 64 + "  /outside.json", "0" * 64 + "  C:\\outside.json"):
            with self.subTest(entry=entry), fixture() as root:
                (root / "SHA256SUMS.txt").write_text(entry + "\n", encoding="utf-8")
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_checksums(root)
        with fixture() as root:
            path = root / "SHA256SUMS.txt"
            text = path.read_text()
            path.write_text(text + text.splitlines()[0] + "\n", encoding="utf-8")
            with self.assertRaisesRegex(verifier.VerificationError, "Duplicate checksum"):
                verifier.verify_checksums(root)

    def test_json_syntax_duplicate_keys_and_nonfinite_values_fail(self):
        for text in ('{"broken":', '{"x":1,"x":2}', '{"x":NaN}'):
            with self.subTest(text=text), fixture() as root:
                (root / "evidence/public_sources.json").write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    verifier.verify_statistics(root)


if __name__ == "__main__":
    unittest.main()
