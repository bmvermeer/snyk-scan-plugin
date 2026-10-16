import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_scan_report_mode import IS_WIN, ROOT, STUBS, ScanHookTest, fixture  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "hooks"))
from lib import install  # noqa: E402

HELPER = os.path.join(ROOT, "hooks", "helper.py")
SAST = fixture("sast_findings.json")

# Installer stub. Logs its arguments, exits with <NAME>_EXIT, and on success (exit 0)
# copies the snyk stub into INST_DIR when INSTALL_SNYK=1, standing in for a real install.
SH_STUB = """#!/bin/sh
printf '%s %s\\n' "{name}" "$*" >> "$INSTALL_LOG"
if [ "${{{upper}_EXIT:-0}}" = "0" ]; then
  [ "$INSTALL_SNYK" = "1" ] && /bin/cp "$SNYK_STUB_SRC" "$INST_DIR/snyk"
  exit 0
fi
echo "{name} failed badly" >&2
exit "${{{upper}_EXIT}}"
"""
CMD_STUB = """@echo off
echo {name} %*>>"%INSTALL_LOG%"
if "%{upper}_EXIT%"=="" (set CODE=0) else (set CODE=%{upper}_EXIT%)
if "%CODE%"=="0" (
  if "%INSTALL_SNYK%"=="1" copy /Y "%SNYK_STUB_SRC%" "%INST_DIR%\\snyk.cmd" >nul
  if "%INSTALL_SNYK%"=="1" for %%F in ("%SNYK_STUB_SRC%") do copy /Y "%%~dpFsnyk_stub.py" "%INST_DIR%\\snyk_stub.py" >nul
  exit /b 0
)
echo {name} failed badly 1>&2
exit /b %CODE%
"""


def make_stub(directory, name):
    ext = ".cmd" if IS_WIN else ""
    path = os.path.join(directory, name + ext)
    with open(path, "w", newline="\r\n" if IS_WIN else "\n") as f:  # cmd.exe needs CRLF
        f.write((CMD_STUB if IS_WIN else SH_STUB).format(name=name, upper=name.upper()))
    os.chmod(path, 0o755)


class InstallTest(ScanHookTest):
    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.tmp, "stubbin")      # holds npm and brew
        self.inst = os.path.join(self.tmp, "installed")   # where a "successful install" puts snyk
        self.home = os.path.join(self.tmp, "home")
        for d in (self.bin, self.inst, self.home):
            os.makedirs(d)
        self.ilog = os.path.join(self.tmp, "install.log")
        make_stub(self.bin, "npm")
        make_stub(self.bin, "brew")
        self.stub_dir = os.path.join(self.tmp, "empty")   # no snyk on PATH
        os.makedirs(self.stub_dir)
        src = os.path.join(STUBS, "snyk.cmd" if IS_WIN else "snyk")
        self.extra = dict(HOME=self.home, USERPROFILE=self.home, LOCALAPPDATA=self.home,
                          PATH=os.pathsep.join([self.bin, self.inst, self.stub_dir]),
                          SNYK_SCAN_PLUGIN_NO_STANDALONE="1", INSTALL_LOG=self.ilog, INST_DIR=self.inst, SNYK_STUB_SRC=src)

    def env(self, **extra):
        e = super().env()
        e.update(self.extra)
        e.update(extra)
        return e

    def installs(self):
        if not os.path.exists(self.ilog):
            return []
        with open(self.ilog, encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]

    def missing_cli_turn(self):
        return self.turn_with("app.py", "print('a longer line')\n")

    def helper(self, *args, **extra):
        cmd = [sys.executable, HELPER, "--session", self.session, "--project", self.project]
        return subprocess.run(cmd + list(args), capture_output=True, text=True,
                              env=self.env(**extra), timeout=60)

    def state(self):
        with open(os.path.join(self.tempdir, "snyk-scan-plugin-%s.json" % self.session)) as f:
            return json.load(f)

    # REQ-12
    def test_req_12_missing_cli_continues_turn_to_ask_and_installs_nothing(self):
        r = self.missing_cli_turn()
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertEqual(d["decision"], "block")
        self.assertIn("Ask the user", d["reason"])
        self.assertIn("Install nothing until the user answers", d["reason"])
        self.assertEqual(self.installs(), [])
        self.assertEqual(self.state()["pending"], "install")

    def test_req_12_reason_embeds_absolute_helper_commands(self):
        d = json.loads(self.missing_cli_turn().stdout)
        self.assertNotIn("CLAUDE_PLUGIN_ROOT", d["reason"])
        self.assertIn(HELPER.replace("\\", "/"), d["reason"])
        self.assertIn('--session "sess-1"', d["reason"])
        self.assertRegex(d["reason"], r'helper\.py" --session "sess-1" --project "[^"]+" install')
        self.assertRegex(d["reason"], r'decline install')

    def test_req_12_helper_install_without_pending_does_nothing(self):
        r = self.helper("install")
        self.assertIn("nothing was installed", r.stdout)
        self.assertEqual(self.installs(), [])

    def test_req_12_continuation_does_not_ask_again(self):
        self.missing_cli_turn()
        r = self.stop(active=True)
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    # REQ-13
    def test_req_13_install_declined_skips_and_is_not_asked_again(self):
        self.missing_cli_turn()
        r = self.helper("decline", "install")
        self.assertIn("declined", r.stdout)
        self.assertTrue(self.state()["install_declined"])
        self.assertIsNone(self.state()["pending"])
        self.write("app.py", "print('yet another longer line')\n")
        r = self.stop()
        data = json.loads(r.stdout)
        self.assertEqual(set(data), {"systemMessage"})
        self.assertIn("not installed", data["systemMessage"])
        self.assertEqual(self.installs(), [])

    def test_req_13_declined_state_survives_new_turn(self):
        self.missing_cli_turn()
        self.helper("decline", "install")
        self.snapshot()
        self.write("app.py", "print('a third, still longer line')\n")
        self.assertNotIn("decision", self.stop().stdout)

    # REQ-14
    def test_req_14_approval_runs_npm_first_and_retries_scan(self):
        self.missing_cli_turn()
        r = self.helper("install", INSTALL_SNYK="1", SNYK_STUB_EXIT="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.installs(), ["npm install -g snyk"])
        self.assertIn("installed", r.stdout)
        self.assertIn("SAST: no issues", r.stdout)
        self.assertEqual(len(self.calls()), 1)
        self.assertIsNone(self.state()["pending"])

    def test_req_14_retry_reports_findings_as_untrusted(self):
        self.missing_cli_turn()
        r = self.helper("install", INSTALL_SNYK="1", SNYK_STUB_EXIT="1", SNYK_STUB_STDOUT=SAST)
        self.assertIn("untrusted", r.stdout)

    # REQ-15
    @unittest.skipIf(IS_WIN, "brew is macOS and Linux only")
    def test_req_15_npm_failure_falls_back_to_brew(self):
        self.missing_cli_turn()
        r = self.helper("install", NPM_EXIT="1", INSTALL_SNYK="1")
        self.assertEqual(self.installs(), ["npm install -g snyk", "brew install snyk-cli"])
        self.assertIn("installed (brew)", r.stdout)

    @unittest.skipIf(IS_WIN, "brew is macOS and Linux only")
    def test_req_15_npm_missing_falls_back_to_brew(self):
        os.remove(os.path.join(self.bin, "npm"))
        out = install.run_install(env=self.env(INSTALL_SNYK="1"), platform="linux")
        self.assertTrue(out.ok)
        self.assertEqual(out.method, "brew")
        self.assertEqual(self.installs(), ["brew install snyk-cli"])

    def test_req_15_windows_never_runs_brew(self):
        out = install.run_install(env=self.env(NPM_EXIT="1"), platform="win32")
        self.assertFalse(out.ok)
        self.assertEqual(self.installs(), ["npm install -g snyk"])
        self.assertNotIn("brew", " ".join(f.method for f in out.failures))

    # REQ-17
    def test_req_17_all_failures_listed_and_scan_skipped(self):
        self.missing_cli_turn()
        r = self.helper("install", NPM_EXIT="1", BREW_EXIT="1")
        self.assertIn("npm install -g snyk", r.stdout)
        self.assertIn("npm failed badly", r.stdout)
        self.assertIn("standalone", r.stdout)
        self.assertNotIn("no issues", r.stdout)
        if not IS_WIN:
            self.assertIn("brew install snyk-cli", r.stdout)
            self.assertIn("brew failed badly", r.stdout)
        self.assertEqual(self.calls(), [])
        self.assertTrue(self.state()["install_failed"])

    def test_req_17_failed_install_is_not_asked_again(self):
        self.missing_cli_turn()
        self.helper("install", NPM_EXIT="1", BREW_EXIT="1")
        self.write("app.py", "print('yet another longer line')\n")
        r = self.stop()
        self.assertNotIn("decision", r.stdout)
        self.assertIn("not installed", json.loads(r.stdout)["systemMessage"])

    def test_req_17_success_without_snyk_on_path_counts_as_failure(self):
        out = install.run_install(env=self.env(INSTALL_SNYK="0"), platform="win32")
        self.assertFalse(out.ok)
        self.assertIn("not found afterwards", out.failures[0].reason)

    def test_req_17_no_installer_available_lists_each(self):
        ext = ".cmd" if IS_WIN else ""
        os.remove(os.path.join(self.bin, "npm" + ext))
        os.remove(os.path.join(self.bin, "brew" + ext))
        out = install.run_install(env=self.env(), platform="linux")
        self.assertEqual([f.method for f in out.failures],
                         ["npm install -g snyk", "brew install snyk-cli", "standalone binary"])


class HelperCliTest(unittest.TestCase):
    def test_decline_rejects_unknown_kind(self):
        r = subprocess.run([sys.executable, HELPER, "--session", "x", "decline", "bogus"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
