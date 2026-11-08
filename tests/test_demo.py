import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import aws_checker

class CheckerTests(unittest.TestCase):
    def test_repeated_evaluation_and_known_failures(self):
        aws_checker.run_all(aws_checker.SIMULATED_AWS_CONFIG)
        first = list(aws_checker.results)
        aws_checker.run_all(aws_checker.SIMULATED_AWS_CONFIG)
        self.assertEqual(first, aws_checker.results)
        self.assertTrue(any(r["control_id"] == "HIPAA-S3-01" and r["status"] == "FAIL" for r in first))

    def test_demo_report_records_mode_and_counts(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / "report.json"
            aws_checker.main(["--demo", "--output", str(path)])
            report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(report["mode"], "demo")
        self.assertEqual(report["summary"]["total"], len(report["checks"]))

    def test_collection_failure_does_not_overwrite_existing_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("existing evidence", encoding="utf-8")
            with patch.object(aws_checker, "collect_live_aws_config", side_effect=RuntimeError("denied")), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                aws_checker.main(["--output", str(path)])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(path.read_text(), "existing evidence")
