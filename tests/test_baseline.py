import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "hooks"))

from lib import baseline, state  # noqa: E402

HAVE_GIT = shutil.which("git") is not None


def write(root, rel, content="x"):
    p = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(content)
    return p


def git(root, *args):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t"] + list(args),
                   cwd=root, check=True, capture_output=True)


class TmpCase(unittest.TestCase):
    def tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d


class DiffTest(TmpCase):
    def test_req_03_no_change_is_empty(self):
        d = self.tmp()
        write(d, "app.js", "a")
        write(d, "package.json", "{}")
        base = baseline.take(d)
        ch = baseline.changes_since(d, base)
        self.assertFalse(ch)
        self.assertEqual((ch.source, ch.dependency), ([], []))

    def test_changes_classified(self):
        d = self.tmp()
        write(d, "app.js", "a")
        write(d, "README.md", "r")
        base = baseline.take(d)
        write(d, "app.js", "changed")
        write(d, "new/mod.py", "n")
        write(d, "package-lock.json", "{}")
        write(d, "README.md", "changed")
        ch = baseline.changes_since(d, base)
        self.assertEqual(ch.source, ["app.js", "new/mod.py"])
        self.assertEqual(ch.dependency, ["package-lock.json"])

    def test_touch_without_content_change_is_not_a_change(self):
        d = self.tmp()
        p = write(d, "app.js", "same")
        base = baseline.take(d)
        os.utime(p, (time.time() + 50, time.time() + 50))
        self.assertFalse(baseline.changes_since(d, base))

    def test_same_size_edit_detected(self):
        d = self.tmp()
        p = write(d, "app.js", "aaaa")
        base = baseline.take(d)
        write(d, "app.js", "bbbb")
        os.utime(p, (time.time() + 5, time.time() + 5))
        self.assertEqual(baseline.changes_since(d, base).source, ["app.js"])

    def test_deleted_file_is_not_a_change(self):
        d = self.tmp()
        p = write(d, "app.js", "a")
        base = baseline.take(d)
        os.remove(p)
        self.assertFalse(baseline.changes_since(d, base))

    def test_req_08_missing_baseline(self):
        d = self.tmp()
        write(d, "app.js", "a")
        self.assertIsNone(baseline.changes_since(d, None))

    def test_only_relevant_files_are_recorded(self):
        d = self.tmp()
        write(d, "app.js")
        write(d, "README.md")
        self.assertEqual(sorted(baseline.take(d)), ["app.js"])


class FileSetTest(TmpCase):
    def test_req_07_fallback_exclusions(self):
        d = self.tmp()
        for rel in ("src/a.js", "node_modules/x/i.js", ".git/h.js", "dist/o.js", "build/o.js",
                    "target/o.java", "venv/l.py", ".venv/l.py", "pkg/__pycache__/c.py"):
            write(d, rel)
        self.assertEqual(sorted(baseline.take(d)), ["src/a.js"])

    @unittest.skipUnless(HAVE_GIT, "git not installed")
    def test_req_07_git_tracked_and_untracked_not_ignored(self):
        d = self.tmp()
        git(d, "init", "-q")
        write(d, ".gitignore", "ignored.js\nnode_modules/\n")
        write(d, "tracked.js")
        git(d, "add", "-A")
        git(d, "commit", "-qm", "init")
        write(d, "untracked.py")
        write(d, "ignored.js")
        write(d, "node_modules/p/i.js")
        # dist is not ignored here, so in git mode it is included (unlike the fallback)
        write(d, "dist/kept.js")
        self.assertEqual(sorted(baseline.take(d)), ["dist/kept.js", "tracked.js", "untracked.py"])

    @unittest.skipUnless(HAVE_GIT, "git not installed")
    def test_git_deleted_tracked_file_ignored(self):
        d = self.tmp()
        git(d, "init", "-q")
        p = write(d, "gone.js")
        git(d, "add", "-A")
        git(d, "commit", "-qm", "init")
        os.remove(p)
        self.assertEqual(baseline.take(d), {})

    @unittest.skipUnless(hasattr(os, "symlink") and sys.platform != "win32", "needs symlinks")
    def test_symlinks_skipped(self):
        d = self.tmp()
        write(d, "real.js")
        os.symlink(os.path.join(d, "real.js"), os.path.join(d, "link.js"))
        self.assertEqual(sorted(baseline.take(d)), ["real.js"])


class StateTest(TmpCase):
    def test_req_09_state_in_temp_not_project(self):
        d = self.tmp()
        write(d, "app.js")
        state.save("sess-1", {"baseline": baseline.take(d)})
        path = state.path_for("sess-1")
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        self.assertTrue(path.startswith(tempfile.gettempdir()))
        self.assertEqual(os.listdir(d), ["app.js"])
        self.assertIn("app.js", state.load("sess-1")["baseline"])

    def test_defaults_and_unsafe_session_id(self):
        s = state.load("../../etc/passwd")
        self.assertIsNone(s["baseline"])
        self.assertFalse(s["install_declined"])
        p = state.path_for("../../etc/passwd")
        self.assertEqual(os.path.dirname(p), tempfile.gettempdir())

    def test_corrupt_state_falls_back_to_defaults(self):
        path = state.path_for("corrupt-1")
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        with open(path, "w") as f:
            f.write("{bad")
        self.assertIsNone(state.load("corrupt-1")["baseline"])


class SnapshotHookTest(TmpCase):
    def run_hook(self, project, session, tmpdir):
        env = dict(os.environ, TMPDIR=tmpdir, TEMP=tmpdir, TMP=tmpdir)
        return subprocess.run([sys.executable, os.path.join(ROOT, "hooks", "snapshot.py")],
                              input=json.dumps({"session_id": session, "cwd": project,
                                                "hook_event_name": "UserPromptSubmit"}),
                              capture_output=True, text=True, env=env)

    def test_req_09_snapshot_silent_and_writes_only_temp(self):
        project, tmpdir = self.tmp(), self.tmp()
        write(project, "app.js")
        r = self.run_hook(project, "s-hook", tmpdir)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
        self.assertEqual(os.listdir(project), ["app.js"])
        files = os.listdir(tmpdir)
        self.assertEqual(len(files), 1)
        with open(os.path.join(tmpdir, files[0])) as f:
            self.assertIn("app.js", json.load(f)["baseline"])

    def test_snapshot_never_fails_on_bad_input(self):
        tmpdir = self.tmp()
        env = dict(os.environ, TMPDIR=tmpdir, TEMP=tmpdir, TMP=tmpdir)
        for stdin in ("", "not json", "[]", json.dumps({"cwd": "/does/not/exist", "session_id": "x"})):
            r = subprocess.run([sys.executable, os.path.join(ROOT, "hooks", "snapshot.py")],
                               input=stdin, capture_output=True, text=True, env=env)
            self.assertEqual((r.returncode, r.stdout), (0, ""), stdin)


class PerformanceTest(TmpCase):
    def make_tree(self, d, n=10000):
        for i in range(n):
            sub = os.path.join(d, "d%d" % (i % 100))
            os.makedirs(sub, exist_ok=True)
            ext = ".js" if i % 2 else ".md"
            with open(os.path.join(sub, "f%d%s" % (i, ext)), "w") as f:
                f.write("x" * 200)

    def test_req_04_overhead_under_500ms_10k_files(self):
        d = self.tmp()
        self.make_tree(d)
        t = time.perf_counter()
        base = baseline.take(d)
        first = time.perf_counter() - t
        t = time.perf_counter()
        ch = baseline.changes_since(d, base)
        again = time.perf_counter() - t
        self.assertFalse(ch)
        self.assertLess(first, 0.5, "baseline took %.3fs" % first)
        self.assertLess(again, 0.5, "no-change diff took %.3fs" % again)

    @unittest.skipUnless(HAVE_GIT, "git not installed")
    def test_req_04_git_repo_10k_files(self):
        d = self.tmp()
        self.make_tree(d)
        git(d, "init", "-q")
        git(d, "add", "-A")
        t = time.perf_counter()
        base = baseline.take(d)
        ch = baseline.changes_since(d, base)
        total = time.perf_counter() - t
        self.assertFalse(ch)
        self.assertLess(total / 2, 0.5, "git mode averaged %.3fs" % (total / 2))


if __name__ == "__main__":
    unittest.main()
