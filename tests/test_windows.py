"""Windows pitfalls that can be checked on any OS (REQ-44).

The real Windows run happens on the CI runner (T14) and in the manual run (T17).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_scan_report_mode import ROOT, SNAPSHOT, ScanHookTest  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "hooks"))
from lib import baseline, cli, install, state, where  # noqa: E402
import scan as scan_hook  # noqa: E402

HELPER = os.path.join(ROOT, "hooks", "helper.py")


class WindowsParityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def touch(self, *parts):
        p = os.path.join(self.tmp, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").close()
        return p

    # A repo must not be able to plant an executable that a hook then runs.
    def test_req_44_which_ignores_cwd_on_windows(self):
        self.touch("repo", "snyk.exe")
        self.touch("bin", "snyk.cmd")
        old = os.getcwd()
        os.chdir(os.path.join(self.tmp, "repo"))
        try:
            found = where.which("snyk", path=os.path.join(self.tmp, "bin"),
                                windows=True, pathext=".COM;.EXE;.BAT;.CMD")
            only_cwd = where.which("snyk", path=os.path.join(self.tmp, "nothing"),
                                   windows=True, pathext=".EXE")
        finally:
            os.chdir(old)
        self.assertEqual(found.lower(), os.path.join(self.tmp, "bin", "snyk.cmd").lower())
        self.assertIsNone(only_cwd)

    def test_req_44_which_skips_relative_path_entries_on_windows(self):
        self.touch("repo", "snyk.exe")
        old = os.getcwd()
        os.chdir(os.path.join(self.tmp, "repo"))
        try:
            self.assertIsNone(where.which("snyk", path=os.pathsep.join(["", "."]),
                                          windows=True, pathext=".EXE"))
        finally:
            os.chdir(old)

    def test_req_44_which_posix_uses_exec_bit(self):
        if os.name == "nt":
            self.skipTest("posix only")
        p = self.touch("bin", "tool")
        self.assertIsNone(where.which("tool", path=os.path.dirname(p), windows=False))
        os.chmod(p, 0o755)
        self.assertEqual(where.which("tool", path=os.path.dirname(p), windows=False), p)

    def test_req_44_git_and_installers_resolved_without_cwd(self):
        # baseline and install must use where.which, not a bare name that CreateProcess
        # would look up in the project directory.
        for mod in (baseline, install, cli):
            with open(mod.__file__.replace(".pyc", ".py"), encoding="utf-8") as f:
                src = f.read()
            self.assertNotIn("shutil.which", src, mod.__name__)
        with open(baseline.__file__.replace(".pyc", ".py"), encoding="utf-8") as f:
            self.assertNotIn('["git",', f.read())

    def test_req_44_helper_command_uses_forward_slashes_on_windows(self):
        cmd = scan_hook.helper_command("s1", "C:\\Users\\me\\proj dir", "scan",
                                       python="C:\\Python39\\python.exe",
                                       helper="C:\\plug in\\hooks\\helper.py", windows=True)
        self.assertNotIn("\\", cmd)
        self.assertIn('"C:/Python39/python.exe"', cmd)
        self.assertIn('"C:/Users/me/proj dir"', cmd)

    def test_req_44_helper_command_posix_unchanged(self):
        cmd = scan_hook.helper_command("s1", "/a b/c", "scan", python="/usr/bin/python3",
                                       helper="/p/hooks/helper.py", windows=False)
        self.assertIn('"/a b/c"', cmd)

    def test_req_44_state_save_retries_locked_replace(self):
        calls = []
        real = os.replace

        def flaky(a, b):
            calls.append(1)
            if len(calls) < 3:
                raise PermissionError("locked")
            return real(a, b)

        d = os.path.join(self.tmp, "t")
        os.makedirs(d)
        old_tmp, tempfile.tempdir = tempfile.tempdir, d
        os.replace = flaky
        try:
            state.save("retry", dict(state.DEFAULTS))
        finally:
            os.replace = real
            tempfile.tempdir = old_tmp
        self.assertEqual(len(calls), 3)
        self.assertEqual([f for f in os.listdir(d) if f.endswith(".tmp")], [])
        self.assertTrue(os.path.exists(os.path.join(d, "snyk-scan-plugin-retry.json")))

    def test_req_44_state_save_cleans_tmp_when_replace_keeps_failing(self):
        real = os.replace
        d = os.path.join(self.tmp, "t")
        os.makedirs(d)
        old_tmp, tempfile.tempdir = tempfile.tempdir, d

        def broken(a, b):
            raise PermissionError("locked")

        os.replace = broken
        try:
            with self.assertRaises(OSError):
                state.save("fail", dict(state.DEFAULTS))
        finally:
            os.replace = real
            tempfile.tempdir = old_tmp
        self.assertEqual(os.listdir(d), [])

    def test_req_44_taskkill_uses_system32_path(self):
        self.assertTrue(cli.taskkill_path({"SystemRoot": "C:\\Windows"}).lower().endswith("taskkill.exe"))
        self.assertIn("System32", cli.taskkill_path({"SystemRoot": "C:\\Windows"}))


class Utf8StdioTest(ScanHookTest):
    """Windows pipes default to the ANSI code page; the hooks must still read UTF-8 JSON."""

    def legacy_env(self, **extra):
        env = self.env(**extra)
        env.update(PYTHONIOENCODING="cp1252", PYTHONUTF8="0")
        return env

    def test_req_44_hook_reads_utf8_stdin_with_legacy_codepage(self):
        proj = os.path.join(self.tmp, "M\u00fcller project")
        os.makedirs(proj)
        with open(os.path.join(proj, "app.py"), "w") as f:
            f.write("x = 1\n")
        payload = json.dumps({"session_id": "u1", "cwd": proj}, ensure_ascii=False).encode("utf-8")
        r = subprocess.run([sys.executable, SNAPSHOT], input=payload, capture_output=True,
                           env=self.legacy_env(), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.tempdir, "snyk-scan-plugin-u1.json"), encoding="utf-8") as f:
            self.assertIn("app.py", json.load(f)["baseline"])

    def test_req_44_helper_prints_non_ascii_with_legacy_codepage(self):
        proj = os.path.join(self.tmp, "p")
        os.makedirs(proj)
        r = subprocess.run([sys.executable, HELPER, "--session", "u2", "--project", proj,
                            "set-mode", "caf\u00e9"], capture_output=True,
                           env=self.legacy_env(), timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("caf\u00e9".encode("utf-8"), r.stdout)


if __name__ == "__main__":
    unittest.main()
