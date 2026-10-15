import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_scan_report_mode import ROOT, ScanHookTest, fixture  # noqa: E402

HELPER = os.path.join(ROOT, "hooks", "helper.py")
COMMANDS = os.path.join(ROOT, "commands")


class CommandsTest(ScanHookTest):
    def helper(self, *args, **extra):
        cmd = [sys.executable, HELPER, "--session", self.session, "--project", self.project]
        return subprocess.run(cmd + list(args), capture_output=True, text=True,
                              env=self.env(**extra), timeout=60)

    def config_path(self):
        return os.path.join(self.project, ".claude", "snyk-plugin.json")

    def read_config(self):
        with open(self.config_path(), encoding="utf-8") as f:
            return f.read()

    def session_state(self):
        p = os.path.join(self.tempdir, "snyk-scan-plugin-%s.json" % self.session)
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)

    # REQ-46
    def test_req_46_valid_mode_creates_config_and_dir(self):
        for mode in ("report", "suggest", "autofix"):
            r = self.helper("set-mode", mode)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(self.read_config()), {"mode": mode})
            self.assertIn(mode, r.stdout)

    def test_req_46_preserves_other_keys(self):
        self.write_config(mode="report", severityThreshold="high", timeoutSeconds=30)
        self.helper("set-mode", "autofix")
        self.assertEqual(json.loads(self.read_config()),
                         {"mode": "autofix", "severityThreshold": "high", "timeoutSeconds": 30})

    def test_req_46_invalid_value_leaves_file_and_lists_valid(self):
        self.write_config(mode="suggest", severityThreshold="high")
        before = self.read_config()
        r = self.helper("set-mode", "yolo")
        self.assertEqual(self.read_config(), before)
        for mode in ("report", "suggest", "autofix"):
            self.assertIn(mode, r.stdout)

    def test_req_46_invalid_value_creates_no_file(self):
        r = self.helper("set-mode", "yolo")
        self.assertFalse(os.path.exists(self.config_path()))
        self.assertFalse(os.path.exists(os.path.join(self.project, ".claude")))
        self.assertIn("autofix", r.stdout)

    def test_req_46_missing_value_lists_valid_and_changes_nothing(self):
        r = self.helper("set-mode")
        self.assertFalse(os.path.exists(self.config_path()))
        for mode in ("report", "suggest", "autofix"):
            self.assertIn(mode, r.stdout)

    def test_req_46_extra_words_rejected(self):
        self.write_config(mode="suggest")
        before = self.read_config()
        r = self.helper("set-mode", "autofix now")
        self.assertEqual(self.read_config(), before)
        self.assertIn("report", r.stdout)

    def test_req_46_broken_config_not_destroyed(self):
        self.write(".claude/snyk-plugin.json", "{ not json")
        r = self.helper("set-mode", "suggest")
        self.assertEqual(self.read_config(), "{ not json")
        self.assertIn("snyk-plugin.json", r.stdout)
        self.assertIn("unchanged", r.stdout)

    def test_req_46_non_object_config_not_destroyed(self):
        self.write(".claude/snyk-plugin.json", "[1, 2]")
        self.helper("set-mode", "suggest")
        self.assertEqual(self.read_config(), "[1, 2]")

    def test_req_46_no_temp_files_left_and_nothing_else_written(self):
        self.helper("set-mode", "suggest")
        self.assertEqual(os.listdir(os.path.join(self.project, ".claude")), ["snyk-plugin.json"])
        self.assertEqual(os.listdir(self.project), [".claude"])

    def test_req_46_new_mode_is_used_by_config_loader(self):
        sys.path.insert(0, os.path.join(ROOT, "hooks"))
        from lib import config
        self.helper("set-mode", "autofix")
        cfg = config.load(self.project)
        self.assertEqual(cfg.mode, "autofix")
        self.assertEqual(cfg.warnings, [])

    # REQ-47
    def test_req_47_scan_runs_both_without_changes(self):
        r = self.helper("scan", SNYK_STUB_EXIT="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertEqual(len([c for c in calls if c.startswith("code test")]), 1)
        self.assertEqual(len([c for c in calls if c.startswith("test --all-projects")]), 1)
        self.assertIn("SAST: no issues", r.stdout)
        self.assertIn("SCA: no issues", r.stdout)

    def test_req_47_scan_reports_findings_as_untrusted(self):
        r = self.helper("scan", SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=fixture("sast_findings.json"))
        self.assertIn("untrusted", r.stdout)

    def test_req_47_scan_failure_not_reported_as_clean(self):
        r = self.helper("scan", SNYK_STUB_EXIT="2")
        self.assertNotIn("no issues", r.stdout)
        self.assertIn("SAST", r.stdout)

    def test_req_47_scan_leaves_session_state_alone(self):
        self.write("app.py", "x = 1\n")
        self.snapshot()
        before = self.session_state()
        self.helper("scan", SNYK_STUB_EXIT="0")
        self.assertEqual(self.session_state(), before)

    def test_req_47_scan_does_not_disturb_next_stop(self):
        self.write("app.py", "# old\n")
        self.snapshot()
        self.write("app.py", "print('a longer line')\n")
        self.helper("scan", SNYK_STUB_EXIT="0")
        self.assertEqual(len(self.calls()), 2)
        r = self.stop(SNYK_STUB_EXIT="0")  # the turn's own scan still happens
        self.assertIn("SAST: no issues", self.message(r))

    def test_req_47_scan_in_suggest_mode_prints_report_without_continuation(self):
        self.write_config(mode="suggest")
        r = self.helper("scan", SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=fixture("sast_findings.json"))
        self.assertIn("SAST", r.stdout)
        self.assertNotIn("decision", r.stdout)

    def test_req_47_scan_uses_config_threshold(self):
        self.write_config(severityThreshold="critical")
        r = self.helper("scan", SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=fixture("sast_findings.json"))
        self.assertEqual(r.returncode, 0)
        self.assertIn("SAST", r.stdout)


class CommandFilesTest(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(COMMANDS, name), encoding="utf-8") as f:
            return f.read()

    def frontmatter(self, text):
        m = re.match(r"---\n(.*?)\n---\n", text, re.S)
        self.assertIsNotNone(m, "missing frontmatter")
        return dict(l.split(":", 1) for l in m.group(1).splitlines() if ":" in l)

    def test_req_46_command_file_snyk_mode(self):
        text = self.read("snyk-mode.md")
        fm = self.frontmatter(text)
        self.assertTrue(fm["description"].strip())
        self.assertIn("helper.py", text)
        self.assertIn("set-mode", text)
        self.assertIn("$ARGUMENTS", text)
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", text)

    def test_req_47_command_file_snyk_scan(self):
        text = self.read("snyk-scan.md")
        fm = self.frontmatter(text)
        self.assertTrue(fm["description"].strip())
        self.assertIn("helper.py", text)
        self.assertIn("scan", text)
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", text)


if __name__ == "__main__":
    unittest.main()
