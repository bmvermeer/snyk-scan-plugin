import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SH = shutil.which("sh")


def hook_commands():
    with open(os.path.join(ROOT, "hooks", "hooks.json"), encoding="utf-8") as f:
        hooks = json.load(f)["hooks"]
    return {ev: hooks[ev][0]["hooks"][0] for ev in hooks}


@unittest.skipUnless(SH and os.name != "nt", "needs a POSIX sh; Windows is covered by CI (T14)")
class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.plugin = os.path.join(self.tmp, "plugin root")  # space on purpose
        os.makedirs(os.path.join(self.plugin, "hooks"))
        self.marker = os.path.join(self.tmp, "ran.txt")
        for name in ("snapshot.py", "scan.py"):
            with open(os.path.join(self.plugin, "hooks", name), "w") as f:
                f.write("import sys\nopen(%r, 'a').write(sys.stdin.read() + '|%s')\n"
                        % (self.marker, name))
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)

    def fake(self, name, body):
        p = os.path.join(self.bin, name)
        with open(p, "w") as f:
            f.write("#!/bin/sh\n" + body + "\n")
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)

    def real_python(self, name="python3"):
        self.fake(name, 'exec "%s" "$@"' % sys.executable)

    def run_hook(self, event, stdin="IN"):
        cmd = hook_commands()[event]["command"].replace("${CLAUDE_PLUGIN_ROOT}", self.plugin)
        env = {"PATH": self.bin}
        return subprocess.run([SH, "-c", cmd], input=stdin, capture_output=True,
                              text=True, env=env, timeout=30)

    def assert_message(self, r):
        self.assertNotEqual(r.returncode, 2)
        self.assertEqual(r.returncode, 0)
        out = r.stdout.strip()
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("Python 3", json.loads(out)["systemMessage"])
        self.assertFalse(os.path.exists(self.marker))

    # REQ-45
    def test_req_45_python_missing_message(self):
        for event in ("UserPromptSubmit", "Stop"):
            self.assert_message(self.run_hook(event))

    def test_req_45_unusable_python_is_skipped(self):
        self.fake("python3", "exit 9009")           # Windows Store stub style
        self.fake("python", "echo 2.7; exit 1")     # Python 2 style
        self.assert_message(self.run_hook("Stop"))

    def test_req_45_python_present_runs_script_with_stdin(self):
        self.real_python()
        for event, script in (("UserPromptSubmit", "snapshot.py"), ("Stop", "scan.py")):
            if os.path.exists(self.marker):
                os.remove(self.marker)
            r = self.run_hook(event, stdin='{"cwd": "C:\\\\x"}')
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout, "")
            with open(self.marker) as f:
                self.assertEqual(f.read(), '{"cwd": "C:\\\\x"}|' + script)

    def test_req_45_falls_back_to_python_after_broken_python3(self):
        self.fake("python3", "exit 9009")
        self.real_python("python")
        r = self.run_hook("Stop")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.marker))

    def test_req_45_falls_back_to_py_launcher(self):
        self.fake("py", '[ "$1" = "-3" ] || exit 1; shift; exec "%s" "$@"' % sys.executable)
        r = self.run_hook("Stop")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.marker))



class LauncherConfigTest(unittest.TestCase):
    def test_hooks_use_bash_shell(self):
        for h in hook_commands().values():
            self.assertEqual(h.get("shell"), "bash")


if __name__ == "__main__":
    unittest.main()
