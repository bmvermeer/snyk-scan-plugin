import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))

from lib import files  # noqa: E402


class ClassifyTest(unittest.TestCase):
    def test_req_01_source_extensions(self):
        for p in ("app.js", "src/App.tsx", "a/b/main.py", "Main.JAVA", "x.go", "lib.rs", "m.kt", "v.vue"):
            self.assertEqual(files.classify(p), "source", p)

    def test_req_02_dependency_names(self):
        names = ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                 "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
                 "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "go.sum", "Gemfile",
                 "Gemfile.lock", "packages.lock.json", "composer.json", "composer.lock", "App.csproj")
        for n in names:
            self.assertEqual(files.classify("sub/dir/" + n), "dependency", n)

    def test_neither(self):
        for p in ("README.md", "notes.txt", "logo.png", "data.json", "Makefile", "page.html", "noext"):
            self.assertIsNone(files.classify(p), p)

    def test_windows_separators(self):
        self.assertEqual(files.classify("src\\app\\main.py"), "source")
        self.assertEqual(files.classify("web\\package.json"), "dependency")

    def test_dependency_wins_over_source(self):
        self.assertEqual(files.classify("build.gradle.kts"), "dependency")


if __name__ == "__main__":
    unittest.main()
