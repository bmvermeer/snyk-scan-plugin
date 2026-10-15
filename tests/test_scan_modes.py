import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_scan_report_mode import IS_WIN, ScanHookTest, fixture  # noqa: E402

SAST = fixture("sast_findings.json")
SCA = fixture("sca_findings_list.json")


def sast_fewer():
    data = json.loads(SAST)
    data["runs"][0]["results"] = data["runs"][0]["results"][:-1]
    return json.dumps(data)


class ModesTest(ScanHookTest):
    def decision(self, r):
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def read_app(self):
        with open(os.path.join(self.project, "app.py"), encoding="utf-8") as f:
            return f.read()

    def findings_turn(self, mode, **cfg):
        self.write_config(mode=mode, **cfg)
        return self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT="1",
                              SNYK_STUB_STDOUT=SAST)

    def test_req_37_suggest_continues_with_summary_and_no_edit_instruction(self):
        d = self.decision(self.findings_turn("suggest"))
        self.assertEqual(d["decision"], "block")
        self.assertIn("SAST:", d["reason"])
        self.assertIn("untrusted", d["reason"])
        self.assertIn("propose", d["reason"])
        self.assertIn("Do not edit", d["reason"])
        self.assertIn("SAST:", d["systemMessage"])
        self.assertEqual(len(self.calls()), 1)

    def test_req_37_suggest_continuation_runs_nothing(self):
        self.findings_turn("suggest")
        before = self.read_app()
        r = self.stop(active=True, SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=SAST)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.read_app(), before)

    def test_req_37_suggest_no_findings_ends_turn(self):
        self.write_config(mode="suggest")
        r = self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT="0")
        self.assertEqual(set(json.loads(r.stdout)), {"systemMessage"})

    def test_req_38_autofix_continues_with_full_output_as_untrusted_data(self):
        d = self.decision(self.findings_turn("autofix"))
        self.assertEqual(d["decision"], "block")
        self.assertIn("untrusted-data-", d["reason"])
        self.assertIn("Fix them now", d["reason"])
        self.assertIn("Sqli", d["reason"])

    def test_req_38_autofix_hostile_output_cannot_close_wrapper(self):
        self.write_config(mode="autofix")
        r = self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT="1",
                           SNYK_STUB_STDOUT=fixture("sast_hostile.json"))
        reason = self.decision(r)["reason"]
        self.assertNotIn("</untrusted-data>", reason)

    def test_req_39_autofix_instruction_limits_edits_to_named_locations(self):
        reason = self.decision(self.findings_turn("autofix"))["reason"]
        self.assertIn("editing only the file and line", reason)
        self.assertIn("manifest and package", reason)
        self.assertIn("and nothing else", reason)
        skill = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "skills", "snyk-scan", "SKILL.md")
        with open(skill, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("file and line", text)
        self.assertIn("manifest and package", text)
        self.assertIn("untrusted", text)

    def test_req_40_rescan_only_scans_that_had_findings(self):
        self.write_config(mode="autofix")
        self.write("app.py", "# old\n")
        self.write("package.json", "{}\n")
        self.snapshot()
        self.write("app.py", "print('a longer line')\n")
        self.write("package.json", '{"name": "a-longer-name"}\n')
        # SAST clean, SCA has findings (one stub exit code for both scans)
        d = self.decision(self.stop(SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=SCA))
        self.assertEqual(d["decision"], "block")
        self.assertEqual(len(self.calls()), 2)
        # sast reported findings only if parsable; SCA output is not SARIF, so only SCA acts
        self.assertIn("SCA full output", d["reason"])
        self.assertNotIn("SAST full output", d["reason"])
        r = self.stop(active=True, SNYK_STUB_EXIT="0")
        calls = self.calls()
        self.assertEqual(len(calls), 3)
        self.assertTrue(calls[2].startswith("test --all-projects"))
        self.assertIn("SCA: ", self.message(r))

    def test_req_41_reports_fixed_and_remaining(self):
        self.findings_turn("autofix")
        r = self.stop(active=True, SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=sast_fewer())
        msg = self.message(r)
        self.assertIn("SAST: 1 fixed, 2 remaining", msg)

    def test_req_41_failed_rescan_is_not_reported_as_fixed(self):
        self.findings_turn("autofix")
        r = self.stop(active=True, SNYK_STUB_EXIT="2", SNYK_STUB_STDERR="boom")
        msg = self.message(r)
        self.assertNotIn("fixed", msg)
        self.assertIn("SAST:", msg)

    def test_req_10_11_40_no_loop_under_autofix(self):
        self.findings_turn("autofix")
        self.assertEqual(len(self.calls()), 1)
        # Claude edits during the continuation: file under scan and an unrelated one.
        self.write("app.py", "print('fixed line, now longer still')\n")
        self.write("other.py", "print('edited in the continuation')\n")
        r = self.stop(active=True, SNYK_STUB_EXIT="0")
        self.assertEqual(len(self.calls()), 2)  # exactly one re-scan
        self.assertIn("SAST: 3 fixed, 0 remaining", self.message(r))
        # Another active Stop: nothing runs, nothing printed.
        r = self.stop(active=True, SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=SAST)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(len(self.calls()), 2)
        # Next turn without new edits: the autofix edits are not reported or scanned (REQ-10).
        self.snapshot()
        r = self.stop(SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=SAST)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(len(self.calls()), 2)

    def test_req_10_rebaseline_even_without_snapshot(self):
        # UserPromptSubmit does not fire on continuations, so scan.py re-baselines itself.
        self.findings_turn("autofix")
        self.write("app.py", "print('fixed line, now longer still')\n")
        self.stop(active=True, SNYK_STUB_EXIT="0")
        r = self.stop(SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=SAST)  # no snapshot in between
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(len(self.calls()), 2)

    def test_req_11_unknown_active_stop_scans_nothing(self):
        self.write_config(mode="autofix")
        self.write("app.py", "# old\n")
        self.snapshot()
        self.write("app.py", "print('a longer line')\n")
        r = self.stop(active=True, SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=SAST)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(self.calls(), [])

    def test_req_43_failed_scan_never_continues_in_suggest_or_autofix(self):
        for mode in ("suggest", "autofix"):
            for code in ("2", "3"):
                self.setUp()
                self.write_config(mode=mode)
                r = self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT=code,
                                   SNYK_STUB_STDERR="some error")
                self.assertNotIn("decision", r.stdout, (mode, code))
                self.assertEqual(set(json.loads(r.stdout)), {"systemMessage"})

    @unittest.skipIf(IS_WIN, "uses a POSIX sleep stub")
    def test_req_43_timeout_never_continues_in_autofix(self):
        slow = os.path.join(self.tmp, "slow")
        os.makedirs(slow)
        stub = os.path.join(slow, "snyk")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nsleep 20\n")
        os.chmod(stub, 0o755)
        self.stub_dir = slow
        self.write_config(mode="autofix", timeoutSeconds=1)
        r = self.turn_with("app.py", "print('a longer line')\n")
        self.assertNotIn("decision", r.stdout)
        self.assertIn("timed out", self.message(r))

    def test_report_mode_unchanged_with_findings(self):
        d = self.decision(self.findings_turn("report"))
        self.assertEqual(set(d), {"systemMessage"})

    def test_severity_threshold_filters_continuation(self):
        self.write_config(mode="autofix", severityThreshold="critical")
        r = self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT="1",
                           SNYK_STUB_STDOUT=SAST)
        self.assertNotIn("decision", r.stdout)


if __name__ == "__main__":
    unittest.main()
