import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))

from lib import config  # noqa: E402


class ConfigTest(unittest.TestCase):
    def project(self, content=None, raw=None):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        if content is not None or raw is not None:
            os.makedirs(os.path.join(d, ".claude"))
            with open(os.path.join(d, ".claude", "snyk-plugin.json"), "w") as f:
                f.write(raw if raw is not None else json.dumps(content))
        return d

    def test_req_35_default_report_no_file(self):
        c = config.load(self.project())
        self.assertEqual((c.mode, c.severity_threshold, c.timeout_seconds), ("report", "low", 120))
        self.assertFalse(c.file_exists)
        self.assertEqual(c.warnings, [])

    def test_valid_config(self):
        c = config.load(self.project({"mode": "autofix", "severityThreshold": "high",
                                      "timeoutSeconds": 30, "extra": 1}))
        self.assertEqual((c.mode, c.severity_threshold, c.timeout_seconds), ("autofix", "high", 30))
        self.assertTrue(c.file_exists)
        self.assertEqual(c.warnings, [])

    def test_req_42_broken_json(self):
        c = config.load(self.project(raw="{nope"))
        self.assertEqual(c.mode, "report")
        self.assertEqual(len(c.warnings), 1)
        self.assertIn("snyk-plugin.json", c.warnings[0])

    def test_req_42_unknown_mode(self):
        c = config.load(self.project({"mode": "yolo"}))
        self.assertEqual(c.mode, "report")
        self.assertIn("yolo", c.warnings[0])

    def test_req_42_not_an_object(self):
        c = config.load(self.project(raw="[1]"))
        self.assertEqual(c.mode, "report")
        self.assertEqual(len(c.warnings), 1)

    def test_req_42_unreadable_is_directory(self):
        d = self.project()
        os.makedirs(os.path.join(d, ".claude", "snyk-plugin.json"))
        c = config.load(d)
        self.assertEqual(c.mode, "report")
        self.assertEqual(len(c.warnings), 1)

    def test_req_48_timeout(self):
        self.assertEqual(config.load(self.project({"timeoutSeconds": 5})).timeout_seconds, 5)
        for bad in (0, -3, "10", 1.5, True, None):
            c = config.load(self.project({"timeoutSeconds": bad}))
            self.assertEqual(c.timeout_seconds, 120, bad)
            self.assertEqual(len(c.warnings), 1, bad)

    def test_req_49_threshold(self):
        for t in ("low", "medium", "high", "critical"):
            self.assertEqual(config.load(self.project({"severityThreshold": t})).severity_threshold, t)
        c = config.load(self.project({"severityThreshold": "severe"}))
        self.assertEqual(c.severity_threshold, "low")
        self.assertEqual(len(c.warnings), 1)

    def test_invalid_field_keeps_other_valid_fields(self):
        c = config.load(self.project({"mode": "suggest", "timeoutSeconds": -1}))
        self.assertEqual((c.mode, c.timeout_seconds), ("suggest", 120))


if __name__ == "__main__":
    unittest.main()
