import ntpath
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))

from lib import cli  # noqa: E402

STUBS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stubs")
IS_WIN = os.name == "nt"


def make_exe(directory, name, posix_body, win_body):
    """Write a small executable script in native form."""
    if IS_WIN:
        path = os.path.join(directory, name + ".cmd")
        with open(path, "w") as f:
            f.write(win_body)
    else:
        path = os.path.join(directory, name)
        with open(path, "w") as f:
            f.write(posix_body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


class CliBase(unittest.TestCase):
    def tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        return d

    def stub_env(self, exit_code=0, stdout=None, stderr=None, log=None):
        env = {"PATH": STUBS + os.pathsep + os.environ.get("PATH", ""),
               "SNYK_STUB_EXIT": str(exit_code)}
        if IS_WIN:
            env["SystemRoot"] = os.environ.get("SystemRoot", "")
            env["PATHEXT"] = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        if stdout is not None:
            env["SNYK_STUB_STDOUT"] = stdout
        if stderr is not None:
            env["SNYK_STUB_STDERR"] = stderr
        if log:
            env["SNYK_STUB_LOG"] = log
        return env

    def scan(self, kind="sast", exit_code=0, stdout=None, stderr=None, timeout=30):
        env = self.stub_env(exit_code, stdout, stderr)
        return cli.run_scan(kind, self.tmp(), timeout, env=env)


class LocateTest(CliBase):
    def test_req_20_standalone_path_posix(self):
        p = cli.standalone_path(platform="linux", home="/home/u", env={})
        self.assertEqual(p, "/home/u/.local/share/snyk-scan-plugin/bin/snyk")

    def test_req_21_standalone_path_windows(self):
        p = cli.standalone_path(platform="win32", home="C:\\Users\\u",
                                env={"LOCALAPPDATA": "C:\\Users\\u\\AppData\\Local"})
        self.assertEqual(p, ntpath.join("C:\\Users\\u\\AppData\\Local", "snyk-scan-plugin", "bin", "snyk.exe"))

    def test_req_20_finds_on_path(self):
        found = cli.find_snyk(env=self.stub_env())
        self.assertIsNotNone(found)
        self.assertTrue(os.path.basename(found).lower().startswith("snyk"))
        self.assertEqual(os.path.dirname(found), STUBS)

    @unittest.skipIf(IS_WIN, "posix standalone layout")
    def test_req_20_finds_standalone_without_path(self):
        home = self.tmp()
        bindir = os.path.join(home, ".local", "share", "snyk-scan-plugin", "bin")
        os.makedirs(bindir)
        exe = make_exe(bindir, "snyk", "#!/bin/sh\nexit 0\n", "")
        found = cli.find_snyk(env={"PATH": self.tmp()}, home=home)
        self.assertEqual(found, exe)

    def test_req_20_not_found(self):
        self.assertIsNone(cli.find_snyk(env={"PATH": self.tmp(), "LOCALAPPDATA": self.tmp()},
                                        home=self.tmp()))

    @unittest.skipUnless(IS_WIN, "windows standalone layout")
    def test_req_21_finds_standalone_without_path_windows(self):
        local = self.tmp()
        bindir = os.path.join(local, "snyk-scan-plugin", "bin")
        os.makedirs(bindir)
        exe = os.path.join(bindir, "snyk.exe")
        open(exe, "w").close()
        found = cli.find_snyk(env={"PATH": self.tmp(), "LOCALAPPDATA": local}, home=self.tmp())
        self.assertEqual(found, exe)

    def test_req_20_missing_cli_result(self):
        r = cli.run_scan("sast", self.tmp(), 5, env={"PATH": self.tmp()}, home=self.tmp())
        self.assertEqual(r.status, cli.NOT_INSTALLED)


class ExitCodeTest(CliBase):
    def test_exit_0_ok(self):
        r = self.scan(exit_code=0, stdout="{}")
        self.assertEqual((r.status, r.exit_code), (cli.OK, 0))
        self.assertEqual(r.stdout.strip(), "{}")

    def test_exit_1_findings(self):
        r = self.scan(exit_code=1, stdout='{"ok": false}')
        self.assertEqual(r.status, cli.FINDINGS)
        self.assertIn("ok", r.stdout)

    def test_req_30_exit_2_failed(self):
        r = self.scan(exit_code=2, stderr="something broke\nsecond line")
        self.assertEqual(r.status, cli.FAILED)
        self.assertEqual(r.message, "scan failed: something broke")

    def test_req_30_exit_3_nothing_to_scan(self):
        r = self.scan(kind="sca", exit_code=3)
        self.assertEqual(r.status, cli.NOTHING_TO_SCAN)
        self.assertEqual(r.message, "nothing to scan")

    def test_req_30_never_ok_on_failure(self):
        for code in (2, 3, 7, 127):
            self.assertNotIn(self.scan(exit_code=code).status, (cli.OK, cli.FINDINGS))

    def test_req_28_unknown_error_first_line(self):
        r = self.scan(exit_code=7, stderr="\nweird failure here\nmore")
        self.assertEqual(r.status, cli.UNKNOWN_ERROR)
        self.assertEqual(r.message, "scan failed: weird failure here")

    def test_req_28_unknown_error_no_text(self):
        r = self.scan(exit_code=7)
        self.assertEqual(r.status, cli.UNKNOWN_ERROR)
        self.assertTrue(r.message.startswith("scan failed:"))
        self.assertIn("7", r.message)

    def test_req_28_exit_2_unrecognised_text(self):
        r = self.scan(exit_code=2, stdout='{"error": "boom"}')
        self.assertTrue(r.message.startswith("scan failed:"))
        self.assertIn("boom", r.message)

    def test_known_auth_strings(self):
        for text in cli.AUTH_ERRORS:
            r = self.scan(exit_code=2, stderr="prefix " + text + " suffix")
            self.assertEqual(r.status, cli.NOT_AUTHENTICATED, text)

    def test_req_27_known_code_disabled_strings(self):
        for text in cli.CODE_DISABLED_ERRORS:
            r = self.scan(exit_code=2, stdout=text)
            self.assertEqual(r.status, cli.CODE_DISABLED, text)
            self.assertIn("Snyk Code", r.message)

    def test_req_27_code_disabled_only_for_sast(self):
        r = self.scan(kind="sca", exit_code=2, stderr=cli.CODE_DISABLED_ERRORS[0])
        self.assertEqual(r.status, cli.FAILED)

    def test_error_strings_ignored_when_findings(self):
        r = self.scan(exit_code=1, stdout="Authentication required in a finding title")
        self.assertEqual(r.status, cli.FINDINGS)

    def test_message_truncated(self):
        r = self.scan(exit_code=2, stderr="x" * 1000)
        self.assertLess(len(r.message), 400)


class ArgsAndTimeoutTest(CliBase):
    def test_req_33_args_are_lists(self):
        cmd = cli.build_command("/bin/snyk", "sast")
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[1:3], ["code", "test"])
        cmd = cli.build_command("/bin/snyk", "sca")
        self.assertEqual(cmd[1:], ["test", "--all-projects", "--json"])

    def test_req_33_no_shell(self):
        import subprocess
        calls = []
        real = subprocess.Popen

        def spy(*a, **kw):
            calls.append((a, kw))
            return real(*a, **kw)

        subprocess.Popen = spy
        try:
            self.scan()
        finally:
            subprocess.Popen = real
        self.assertTrue(calls)
        args, kw = calls[0]
        self.assertIsInstance(args[0], list)
        self.assertFalse(kw.get("shell", False))

    def test_req_33_hostile_cwd_not_interpolated(self):
        d = os.path.join(self.tmp(), "a b; echo pwned $(x)")
        os.makedirs(d)
        log = os.path.join(self.tmp(), "log.txt")
        env = self.stub_env(log=log)
        r = cli.run_scan("sast", d, 30, env=env)
        self.assertEqual(r.status, cli.OK)
        with open(log) as f:
            self.assertNotIn("pwned", f.read())

    def test_runs_in_cwd_and_logs_args(self):
        log = os.path.join(self.tmp(), "log.txt")
        cli.run_scan("sca", self.tmp(), 30, env=self.stub_env(log=log))
        with open(log) as f:
            self.assertIn("--all-projects", f.read())

    def test_req_29_timeout_kills_and_reports(self):
        d = self.tmp()
        marker = os.path.join(d, "survived.txt")
        make_exe(d, "snyk",
                 "#!/bin/sh\n(sleep 3; echo x > '%s') &\nsleep 30\n" % marker,
                 "@echo off\nping -n 30 127.0.0.1 >nul\n")
        env = {"PATH": d + os.pathsep + os.environ.get("PATH", "")}
        if IS_WIN:
            env["SystemRoot"] = os.environ.get("SystemRoot", "")
            env["PATHEXT"] = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        start = time.time()
        r = cli.run_scan("sast", self.tmp(), 1, env=env)
        self.assertLess(time.time() - start, 15)
        self.assertEqual(r.status, cli.TIMED_OUT)
        self.assertEqual(r.message, "timed out")
        if not IS_WIN:
            time.sleep(4)
            self.assertFalse(os.path.exists(marker), "child process survived the timeout")


class RealCliFixtureTest(unittest.TestCase):
    """Outputs captured from the real Snyk CLI 1.1308.0 (paths sanitised)."""

    @staticmethod
    def _load(name):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_cli", name)
        with open(path, encoding="utf-8") as f:
            return f.read()

    def test_req_30_real_exit_3_no_projects(self):
        for kind, name in (("sca", "no_projects_sca.json"), ("sast", "no_projects_sast.json")):
            res = cli.classify(kind, 3, self._load(name), "")
            self.assertEqual(res.status, cli.NOTHING_TO_SCAN)
            self.assertEqual(res.message, "nothing to scan")

    def test_req_30_real_exit_2_failed(self):
        res = cli.classify("sca", 2, self._load("failed_invalid_manifest_sca.json"), "")
        self.assertEqual(res.status, cli.FAILED)
        self.assertTrue(res.message.startswith("scan failed:"))

    def test_req_28_real_failure_message_has_reason(self):
        # Real CLI prints pretty JSON on stdout with empty stderr, so the first
        # line is "{". The message should carry the "error" field instead.
        res = cli.classify("sca", 2, self._load("failed_invalid_manifest_sca.json"), "")
        self.assertIn("failed to get dependency graph", res.message)

    def test_req_28_real_not_authenticated(self):
        for kind, name in (("sast", "auth_required_sast.json"), ("sca", "auth_required_sca.json")):
            res = cli.classify(kind, 2, self._load(name), "")
            self.assertEqual(res.status, cli.NOT_AUTHENTICATED)


class NoTokenAccessTest(unittest.TestCase):
    def test_req_26_source_does_not_touch_token_or_auth_config(self):
        src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "hooks", "lib", "cli.py")
        with open(src, encoding="utf-8") as f:
            text = f.read().lower()
        self.assertNotIn("snyk_token", text)
        self.assertNotIn("configstore", text)


if __name__ == "__main__":
    unittest.main()
