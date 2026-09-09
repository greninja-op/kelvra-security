"""Focused tests for GET /api/report/status (report freshness, read-only)."""
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from src.api import app
from src.report_status import REPORT_FILENAME, REPORT_PATH, get_report_status, parse_report_text


class TestReportStatus(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.report_text = REPORT_PATH.read_text(encoding="utf-8")

    def test_status_shape(self):
        res = self.client.get("/api/report/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["report"], REPORT_FILENAME)
        self.assertIn("cadence", data)
        self.assertIn("automated", data["cadence"])
        self.assertIn("manual", data["cadence"])
        self.assertIn("next_manual_due", data["cadence"])
        self.assertIn("last_audit", data)
        self.assertIn("freshness_rule", data)
        self.assertIn("notes", data)
        self.assertIsInstance(data["notes"], list)

    def test_cadence_values_match_file(self):
        data = self.client.get("/api/report/status").json()
        cadence = data["cadence"]
        # Each non-null value must appear verbatim in the live file (no fabrication).
        for value in (cadence["automated"], cadence["manual"],
                      cadence["next_manual_due"], data["last_audit"]):
            self.assertIsNotNone(value, "expected live parse of current report to succeed")
            self.assertIn(value, self.report_text)
        self.assertIsNotNone(data["freshness_rule"])
        self.assertIn("same commit", data["freshness_rule"])
        # Spot-check the known current values.
        self.assertIn("every CI build", cadence["automated"])
        self.assertIn("quarterly", cadence["manual"])
        self.assertEqual(cadence["next_manual_due"], "2026-12-08")
        self.assertEqual(data["last_audit"], "2026-09-08")

    def test_null_honesty_on_unparseable_text(self):
        parsed = parse_report_text("no dates or cadence here\njust prose\n")
        self.assertEqual(parsed, (None, None, None, None, None))

    def test_null_honesty_on_missing_file(self):
        payload = get_report_status(report_path=Path(tempfile.gettempdir()) / "does-not-exist-kelvra.md")
        self.assertEqual(payload["report"], REPORT_FILENAME)
        self.assertEqual(payload["cadence"],
                         {"automated": None, "manual": None, "next_manual_due": None})
        self.assertIsNone(payload["last_audit"])
        self.assertIsNone(payload["freshness_rule"])
        self.assertTrue(payload["notes"], "expected honest note explaining the nulls")


if __name__ == "__main__":
    unittest.main()
