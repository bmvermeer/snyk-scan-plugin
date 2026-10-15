import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUBS = os.path.join(ROOT, "tests", "stubs")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
SNAPSHOT = os.path.join(ROOT, "hooks", "snapshot.py")
SCAN = os.path.join(ROOT, "hooks", "scan.py")
IS_WIN = sys.platform == "win32"


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


class ScanHookTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = os.path.join(self.tmp, "project")
        self.tempdir = os.path.join(self.tmp, "tmp")
        self.log = os.path.join(self.tmp, "snyk.log")
        os.makedirs(self.project)
        os.makedirs(self.tempdir)
        self.session = "sess-1"
        self.stub_dir = STUBS

    def env(self, **extra):
        env = dict(os.environ)
        env.pop("SNYK_TOKEN", None)
        env.update(TMPDIR=self.tempdir, TEMP=self.tempdir, TMP=self.tempdir,
                   SNYK_STUB_LOG=self.log)
        env["PATH"] = self.stub_dir + os.pathsep + env["PATH"]
        env.update(extra)
        return env

    def write(self, rel, text):
        path = os.path.join(self.project, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def hook(self, script, event, active=False, **extra):
        payload = {"session_id": self.session, "cwd": self.project,
                   "hook_event_name": event, "stop_hook_active": active}
        return subprocess.run([sys.executable, script], input=json.dumps(payload),
                              capture_output=True, text=True, env=self.env(**extra), timeout=60)

    def snapshot(self):
        return self.hook(SNAPSHOT, "UserPromptSubmit")

    def stop(self, active=False, **extra):
        return self.hook(SCAN, "Stop", active, **extra)

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]

    def message(self, r):
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(set(data), {"systemMessage"})
        return data["systemMessage"]

    def write_config(self, **cfg):
        self.write(".claude/snyk-plugin.json", json.dumps(cfg))

    def turn_with(self, rel, text, **extra):
        self.write(rel, "# old\n")
        self.snapshot()
        self.write(rel, text)
        return self.stop(**extra)


class ReportModeTest(ScanHookTest):
    def test_req_01_source_change_runs_sast_once(self):
        r = self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT="0")
        self.assertEqual(len(self.calls()), 1)
        self.assertTrue(self.calls()[0].startswith("code test"))
        self.assertIn("SAST: no issues", self.message(r))

    def test_req_01_findings_reported_as_untrusted_data(self):
        r = self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT="1",
                           SNYK_STUB_STDOUT=json.dumps(json.loads(fixture("sast_findings.json"))))
        msg = self.message(r)
        self.assertIn("SAST:", msg)
        self.assertIn("untrusted", msg)

    def test_req_02_dependency_change_runs_sca_all_projects(self):
        r = self.turn_with("package.json", '{"name": "a-longer-name"}\n', SNYK_STUB_EXIT="0")
        self.assertEqual(len(self.calls()), 1)
        self.assertTrue(self.calls()[0].startswith("test --all-projects"))
        self.assertIn("SCA: no issues", self.message(r))

    def test_req_05_deps_only_no_sast(self):
        self.turn_with("requirements.txt", "requests==2.0\n")
        self.assertEqual([c for c in self.calls() if c.startswith("code")], [])
        self.assertEqual(len(self.calls()), 1)

    def test_req_06_source_only_no_sca(self):
        self.turn_with("main.go", "package main // changed\n")
        self.assertEqual([c for c in self.calls() if not c.startswith("code")], [])
        self.assertEqual(len(self.calls()), 1)

    def test_both_change_run_each_once(self):
        self.write("a.py", "x\n")
        self.write("go.mod", "module a\n")
        self.snapshot()
        self.write("a.py", "xx\n")
        self.write("go.mod", "module abc\n")
        r = self.stop()
        self.assertEqual(len(self.calls()), 2)
        msg = self.message(r)
        self.assertIn("SAST", msg)
        self.assertIn("SCA", msg)

    def test_req_03_no_change_silent(self):
        self.write("app.py", "print(1)\n")
        self.snapshot()
        r = self.stop()
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(self.calls(), [])

    def test_req_03_irrelevant_change_silent(self):
        self.write("a.py", "x\n")
        self.snapshot()
        self.write("notes.txt", "hello\n")
        r = self.stop()
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(self.calls(), [])

    def test_req_08_missing_baseline(self):
        self.write("app.py", "print(1)\n")
        r = self.stop()
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(self.calls(), [])
        # a baseline was saved: a later change is now detected
        self.write("app.py", "print(1234)\n")
        self.stop()
        self.assertEqual(len(self.calls()), 1)

    def test_req_11_no_scan_on_own_continuation(self):
        r = self.turn_with("app.py", "print('a longer line')\n", active=True)
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(self.calls(), [])

    def test_req_35_hint_once_per_session_without_config(self):
        r = self.turn_with("app.py", "print('a longer line')\n")
        self.assertIn("/snyk-mode", self.message(r))
        self.write("app.py", "print('an even longer line')\n")
        r2 = self.stop()
        self.assertEqual(len(self.calls()), 2)
        self.assertNotIn("/snyk-mode", self.message(r2))

    def test_req_35_no_hint_with_config(self):
        self.write_config(mode="report")
        r = self.turn_with("app.py", "print('a longer line')\n")
        self.assertNotIn("/snyk-mode", self.message(r))

    def test_config_warnings_shown(self):
        self.write_config(mode="bogus")
        r = self.turn_with("app.py", "print('a longer line')\n")
        self.assertIn("unknown mode", self.message(r))

    def test_req_43_failed_scan_ends_turn(self):
        r = self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT="2",
                           SNYK_STUB_STDERR="boom")
        msg = self.message(r)
        self.assertIn("scan failed", msg)
        self.assertNotIn("no issues", msg)
        self.assertNotIn("decision", r.stdout)

    def test_req_43_not_installed_skips(self):
        self.stub_dir = os.path.join(self.tmp, "empty")
        os.makedirs(self.stub_dir)
        home = os.path.join(self.tmp, "home")
        os.makedirs(home)
        # An install approval is the one allowed continuation (REQ-12, test_install.py);
        # once declined, the scan is skipped and the turn ends.
        with open(os.path.join(self.tempdir, "snyk-scan-plugin-sess-1.json"), "w") as f:
            json.dump({"install_declined": True}, f)
        r = self.turn_with("app.py", "print('a longer line')\n", HOME=home, USERPROFILE=home,
                           LOCALAPPDATA=home, PATH=self.stub_dir)
        self.assertIn("not installed", self.message(r))
        self.assertNotIn("decision", r.stdout)

    def test_req_43_not_authenticated_skips(self):
        r = self.turn_with("app.py", "print('a longer line')\n", SNYK_STUB_EXIT="2",
                           SNYK_STUB_STDERR="Authentication error (SNYK-0005)")
        # The one-time approval prompt (REQ-23) is the allowed continuation (REQ-43).
        d = json.loads(r.stdout)
        self.assertIn("not authenticated", d["systemMessage"])
        self.assertEqual(d["decision"], "block")
        r = self.stop(active=True)  # asked once, then the turn ends
        self.assertEqual(r.stdout, "")

    @unittest.skipIf(IS_WIN, "uses a POSIX sleep stub")
    def test_req_43_timeout_ends_turn(self):
        slow = os.path.join(self.tmp, "slow")
        os.makedirs(slow)
        stub = os.path.join(slow, "snyk")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nsleep 20\n")
        os.chmod(stub, 0o755)
        self.stub_dir = slow
        self.write_config(mode="report", timeoutSeconds=1)
        r = self.turn_with("app.py", "print('a longer line')\n")
        msg = self.message(r)
        self.assertIn("timed out", msg)
        self.assertNotIn("decision", r.stdout)

    def test_garbage_stdin_never_crashes(self):
        r = subprocess.run([sys.executable, SCAN], input="not json", capture_output=True,
                           text=True, env=self.env())
        self.assertEqual((r.returncode, r.stdout), (0, ""))


class NoTokenAccessTest(unittest.TestCase):
    def test_req_26_scan_source_does_not_touch_token_or_auth_config(self):
        with open(SCAN, encoding="utf-8") as f:
            text = f.read().lower()
        self.assertNotIn("snyk_token", text)
        self.assertNotIn("configstore", text)

    def test_req_26_token_not_echoed(self):
        # A token in the environment never reaches the output.
        t = ScanHookTest("setUp")
        t.setUp()
        try:
            r = t.turn_with("app.py", "print('a longer line')\n", SNYK_TOKEN="sekrit-token-value")
            self.assertNotIn("sekrit-token-value", r.stdout + r.stderr)
        finally:
            shutil.rmtree(t.tmp, True)


if __name__ == "__main__":
    unittest.main()
