import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_scan_report_mode import IS_WIN, ROOT, ScanHookTest  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "hooks"))
from lib import cli  # noqa: E402

HELPER = os.path.join(ROOT, "hooks", "helper.py")


class AuthTest(ScanHookTest):
    def setUp(self):
        super().setUp()
        self.authed = os.path.join(self.tmp, "authed")  # created by a successful stub login

    def env(self, **extra):
        e = super().env()
        e["SNYK_STUB_AUTHED_FILE"] = self.authed
        e.update(extra)
        return e

    def helper(self, *args, **extra):
        cmd = [sys.executable, HELPER, "--session", self.session, "--project", self.project]
        return subprocess.run(cmd + list(args), capture_output=True, text=True,
                              env=self.env(**extra), timeout=60)

    def state(self):
        with open(os.path.join(self.tempdir, "snyk-scan-plugin-%s.json" % self.session)) as f:
            return json.load(f)

    def unauth_turn(self):
        return self.turn_with("app.py", "print('a longer line')\n")

    def auth_calls(self):
        return [c for c in self.calls() if c.startswith("auth")]

    def scan_calls(self):
        return [c for c in self.calls() if not c.startswith("auth")]

    # REQ-23
    def test_req_23_not_authenticated_continues_turn_to_ask_and_runs_no_auth(self):
        r = self.unauth_turn()
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertEqual(d["decision"], "block")
        self.assertIn("snyk auth", d["reason"])
        self.assertIn("Ask the user", d["reason"])
        self.assertEqual(self.auth_calls(), [])
        self.assertEqual(self.state()["pending"], "auth")

    def test_req_23_reason_embeds_absolute_helper_commands(self):
        d = json.loads(self.unauth_turn().stdout)
        self.assertNotIn("CLAUDE_PLUGIN_ROOT", d["reason"])
        self.assertIn(HELPER, d["reason"])
        self.assertIn('--session "sess-1"', d["reason"])
        self.assertRegex(d["reason"], r'helper\.py" --session "sess-1" --project "[^"]+" auth')
        self.assertRegex(d["reason"], r'decline auth')

    def test_req_23_continuation_does_not_ask_again(self):
        self.unauth_turn()
        r = self.stop(active=True)
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_req_23_helper_auth_without_pending_does_nothing(self):
        r = self.helper("auth")
        self.assertIn("No Snyk authentication is pending", r.stdout)
        self.assertEqual(self.auth_calls(), [])

    # REQ-24
    def test_req_24_approval_runs_auth_then_retries_scan_once(self):
        self.unauth_turn()
        before = len(self.scan_calls())
        r = self.helper("auth")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.auth_calls(), ["auth"])
        self.assertEqual(len(self.scan_calls()) - before, 1)
        self.assertIn("authenticated", r.stdout)
        self.assertIn("SAST: no issues", r.stdout)
        self.assertIsNone(self.state()["pending"])

    def test_req_24_retry_reports_findings_as_untrusted(self):
        from test_scan_report_mode import fixture
        self.unauth_turn()
        r = self.helper("auth", SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=fixture("sast_findings.json"))
        self.assertIn("untrusted", r.stdout)

    def test_req_24_retry_is_not_repeated_when_still_unauthenticated(self):
        self.unauth_turn()
        before = len(self.scan_calls())
        # Login "succeeds" but the stub is not authenticated afterwards.
        r = self.helper("auth", SNYK_STUB_AUTHED_FILE=os.path.join(self.tmp, "no", "such", "file"))
        self.assertEqual(len(self.scan_calls()) - before, 1)
        self.assertIn("not authenticated", r.stdout)
        self.assertTrue(self.state()["auth_failed"])

    def test_req_24_auth_runs_only_once_for_two_calls(self):
        self.unauth_turn()
        self.helper("auth")
        r = self.helper("auth")
        self.assertIn("No Snyk authentication is pending", r.stdout)
        self.assertEqual(self.auth_calls(), ["auth"])

    # REQ-25
    def test_req_25_decline_names_reason_and_is_not_asked_again(self):
        self.unauth_turn()
        r = self.helper("decline", "auth")
        self.assertIn("declined", r.stdout)
        self.assertTrue(self.state()["auth_declined"])
        self.assertIsNone(self.state()["pending"])
        self.write("app.py", "print('yet another longer line')\n")
        r = self.stop()
        d = json.loads(r.stdout)
        self.assertEqual(set(d), {"systemMessage"})
        self.assertIn("not authenticated", d["systemMessage"])
        self.assertEqual(self.auth_calls(), [])

    def test_req_25_declined_state_survives_new_turn(self):
        self.unauth_turn()
        self.helper("decline", "auth")
        self.snapshot()
        self.write("app.py", "print('a third, still longer line')\n")
        self.assertNotIn("decision", self.stop().stdout)

    def test_req_25_auth_failure_reports_reason_skips_scan_and_is_not_asked_again(self):
        self.unauth_turn()
        before = len(self.scan_calls())
        r = self.helper("auth", SNYK_STUB_AUTH_EXIT="2", SNYK_STUB_AUTH_STDERR="browser login failed")
        self.assertIn("authentication failed", r.stdout.lower())
        self.assertIn("browser login failed", r.stdout)
        self.assertNotIn("no issues", r.stdout)
        self.assertEqual(len(self.scan_calls()) - before, 0)
        self.assertTrue(self.state()["auth_failed"])
        self.assertIsNone(self.state()["pending"])
        self.write("app.py", "print('yet another longer line')\n")
        r = self.stop()
        self.assertNotIn("decision", r.stdout)
        self.assertIn("not authenticated", json.loads(r.stdout)["systemMessage"])

    @unittest.skipIf(IS_WIN, "uses a POSIX sleep stub")
    def test_req_25_auth_timeout_is_reported_as_timeout(self):
        slow = os.path.join(self.tmp, "slow")
        os.makedirs(slow)
        stub = os.path.join(slow, "snyk")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nsleep 20\n")
        os.chmod(stub, 0o755)
        ok, reason = cli.run_auth(self.project, 1, env=dict(os.environ, PATH=slow + os.pathsep + os.environ["PATH"]))
        self.assertFalse(ok)
        self.assertIn("timed out", reason)

    def test_req_25_auth_default_timeout_is_generous(self):
        self.assertGreaterEqual(cli.AUTH_TIMEOUT, 120)

    def test_req_25_cli_missing_during_auth_is_a_failure(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        ok, reason = cli.run_auth(self.project, 5, env={"PATH": empty, "HOME": empty,
                                                         "USERPROFILE": empty, "LOCALAPPDATA": empty})
        self.assertFalse(ok)
        self.assertIn("not found", reason)

    # REQ-26
    def test_req_26_token_not_echoed_or_passed_on_the_command_line(self):
        self.unauth_turn()
        r = self.helper("auth", SNYK_TOKEN="sekrit-token-value")
        self.assertNotIn("sekrit-token-value", r.stdout + r.stderr)
        self.assertFalse(any("sekrit" in c for c in self.calls()))

    def test_req_26_source_does_not_touch_token_or_auth_config(self):
        for rel in (("hooks", "helper.py"), ("hooks", "scan.py"), ("hooks", "lib", "cli.py"),
                    ("hooks", "lib", "state.py"), ("hooks", "lib", "report.py")):
            with open(os.path.join(ROOT, *rel), encoding="utf-8") as f:
                text = f.read().lower()
            self.assertNotIn("snyk_token", text, rel)
            self.assertNotIn("configstore", text, rel)
            self.assertNotIn(".config/configstore", text, rel)


if __name__ == "__main__":
    unittest.main()
