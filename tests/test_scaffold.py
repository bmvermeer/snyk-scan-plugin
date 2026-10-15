import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUBS = os.path.join(ROOT, "tests", "stubs")


def run_stub(exit_code, stdout="", stderr=""):
    env = dict(os.environ, SNYK_STUB_EXIT=str(exit_code),
               SNYK_STUB_STDOUT=stdout, SNYK_STUB_STDERR=stderr)
    env["PATH"] = STUBS + os.pathsep + env["PATH"]
    name = "snyk.cmd" if sys.platform == "win32" else "snyk"
    return subprocess.run([os.path.join(STUBS, name), "code", "test"], env=env,
                          capture_output=True, text=True)


class ScaffoldTest(unittest.TestCase):
    def test_manifest_version(self):
        with open(os.path.join(ROOT, ".claude-plugin", "plugin.json")) as f:
            self.assertEqual(json.load(f)["version"], "0.1.0")

    def test_hooks_json_declares_both_hooks(self):
        with open(os.path.join(ROOT, "hooks", "hooks.json")) as f:
            hooks = json.load(f)["hooks"]
        self.assertEqual(set(hooks), {"UserPromptSubmit", "Stop"})

    def test_stub_scripted_exit_codes(self):
        for code in (0, 1, 2, 3):
            self.assertEqual(run_stub(code).returncode, code)

    def test_stub_stdout(self):
        self.assertIn('{"ok":true}', run_stub(0, stdout='{"ok":true}').stdout)


if __name__ == "__main__":
    unittest.main()
