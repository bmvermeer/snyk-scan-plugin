import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "hooks"))
from lib import cli, standalone  # noqa: E402

with open(os.path.join(ROOT, "tests", "fixtures", "release.json"), encoding="utf-8") as _f:
    RELEASE = _f.read()
BINARY = b"#!/bin/sh\necho fake snyk\n"
GOOD_SUM = hashlib.sha256(BINARY).hexdigest()


class FakeOpener:
    """Stands in for the network: serves bodies by URL and records every request."""

    def __init__(self, bodies):
        self.bodies = bodies
        self.requested = []

    def open(self, url, timeout=None):
        self.requested.append(url)
        if url not in self.bodies:
            raise OSError("404 for %s" % url)
        body = self.bodies[url]
        return io.BytesIO(body if isinstance(body, bytes) else body.encode())


def bodies_for(name, binary=BINARY, checksum=None, release=RELEASE):
    rel = json.loads(release) if release.lstrip().startswith("{") else None
    b = {standalone.RELEASE_URL: release}
    if rel:
        asset = rel["assets"].get(name)
        if asset:
            b[asset["url"]] = binary
            b[asset["sha256Url"]] = (checksum or hashlib.sha256(binary).hexdigest()) + "  " + name + "\n"
    return b


class StandaloneTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)

    def run_install(self, bodies, platform="linux", machine="x86_64", musl=False):
        self.op = FakeOpener(bodies)
        return standalone.install(opener=self.op, platform=platform, machine=machine,
                                  musl=musl, home=self.home, env={"LOCALAPPDATA": self.home})

    def dest(self, platform="linux"):
        return cli.standalone_path(platform=platform, home=self.home, env={"LOCALAPPDATA": self.home})

    # REQ-18
    def test_req_18_asset_selection_per_os_and_cpu(self):
        pick = standalone.asset_name
        self.assertEqual(pick("darwin", "x86_64", False), "snyk-macos")
        self.assertEqual(pick("darwin", "arm64", False), "snyk-macos-arm64")
        self.assertEqual(pick("linux", "x86_64", False), "snyk-linux")
        self.assertEqual(pick("linux", "aarch64", False), "snyk-linux-arm64")
        self.assertEqual(pick("linux", "x86_64", True), "snyk-alpine")
        self.assertEqual(pick("linux", "arm64", True), "snyk-alpine-arm64")
        self.assertEqual(pick("win32", "AMD64", False), "snyk-win.exe")
        self.assertIsNone(pick("linux", "riscv64", False))
        self.assertIsNone(pick("freebsd13", "x86_64", False))

    def test_req_18_alpine_detection(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        rel = os.path.join(d, "alpine-release")
        self.assertFalse(standalone.is_musl(release_file=rel, ldd_output=""))
        self.assertFalse(standalone.is_musl(release_file=rel, ldd_output="ldd (GNU libc) 2.35"))
        self.assertTrue(standalone.is_musl(release_file=rel, ldd_output="musl libc (x86_64)\nVersion 1.2.4"))
        with open(rel, "w") as f:
            f.write("3.19.0\n")
        self.assertTrue(standalone.is_musl(release_file=rel, ldd_output=""))

    def test_req_18_downloads_selected_asset_and_makes_it_executable(self):
        r = self.run_install(bodies_for("snyk-linux-arm64"), machine="aarch64")
        self.assertIsNone(r)
        dest = self.dest()
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), BINARY)
        if os.name != "nt":
            self.assertTrue(os.access(dest, os.X_OK))
        self.assertEqual(self.op.requested[0], "https://downloads.snyk.io/cli/stable/release.json")
        self.assertTrue(any(u.endswith("/snyk-linux-arm64") for u in self.op.requested))
        self.assertEqual(os.listdir(os.path.dirname(dest)), ["snyk"])  # no temp file left

    def test_req_18_alpine_asset_downloaded_when_musl(self):
        self.assertIsNone(self.run_install(bodies_for("snyk-alpine"), musl=True))
        self.assertTrue(any(u.endswith("/snyk-alpine") for u in self.op.requested))

    def test_req_18_url_validator_rejects_hostile_urls(self):
        ok = "https://downloads.snyk.io/cli/stable/release.json"
        self.assertEqual(standalone.validate_url(ok), ok)
        for bad in ["http://downloads.snyk.io/x",
                    "https://downloads.snyk.io.evil.com/x",
                    "https://evil.com/downloads.snyk.io",
                    "https://downloads.snyk.io@evil.com/x",
                    "https://evil.com@downloads.snyk.io/x",
                    "https://downloads.snyk.io:8443/x",
                    "https://user:pw@downloads.snyk.io/x",
                    "https://DOWNLOADS.snyk.io.evil.com/x",
                    "https://downloads.snyk.io\\@evil.com/x",
                    "ftp://downloads.snyk.io/x", "file:///etc/passwd", "//downloads.snyk.io/x", "", None]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                standalone.validate_url(bad)

    def test_req_18_redirects_to_other_hosts_are_rejected(self):
        h = standalone.RestrictedRedirectHandler()
        req = urllib.request.Request("https://downloads.snyk.io/a")
        with self.assertRaises(ValueError):
            h.redirect_request(req, None, 302, "Found", {}, "https://evil.com/a")
        with self.assertRaises(ValueError):
            h.redirect_request(req, None, 302, "Found", {}, "http://downloads.snyk.io/a")
        self.assertIsNotNone(h.redirect_request(req, None, 302, "Found", {}, "https://downloads.snyk.io/b"))

    def test_req_18_asset_url_on_other_host_is_refused_and_never_fetched(self):
        rel = json.loads(RELEASE)
        rel["assets"]["snyk-linux"]["url"] = "https://evil.com/snyk-linux"
        b = bodies_for("snyk-linux", release=json.dumps(rel))
        b["https://evil.com/snyk-linux"] = BINARY
        r = self.run_install(b)
        self.assertIn("no standalone binary available", r.reason)
        self.assertNotIn("https://evil.com/snyk-linux", self.op.requested)
        self.assertFalse(os.path.exists(self.dest()))

    # REQ-19
    def test_req_19_checksum_mismatch_deletes_file(self):
        r = self.run_install(bodies_for("snyk-linux", checksum="0" * 64))
        self.assertEqual(r.reason, "checksum mismatch")
        self.assertFalse(os.path.exists(self.dest()))
        bindir = os.path.dirname(self.dest())
        self.assertEqual(os.listdir(bindir) if os.path.isdir(bindir) else [], [])

    def test_req_19_mismatch_keeps_an_existing_good_install(self):
        self.assertIsNone(self.run_install(bodies_for("snyk-linux")))
        r = self.run_install(bodies_for("snyk-linux", binary=b"tampered", checksum=GOOD_SUM))
        self.assertEqual(r.reason, "checksum mismatch")
        with open(self.dest(), "rb") as f:
            self.assertEqual(f.read(), BINARY)

    def test_req_19_inline_sha256_field_is_ignored(self):
        rel = json.loads(RELEASE)
        rel["assets"]["snyk-linux"]["sha256"] = GOOD_SUM  # matches the binary, but must not be used
        b = bodies_for("snyk-linux", checksum="f" * 64, release=json.dumps(rel))
        self.assertEqual(self.run_install(b).reason, "checksum mismatch")

    def test_req_19_unreadable_checksum_file_fails(self):
        b = bodies_for("snyk-linux", checksum="not-a-hash")
        self.assertEqual(self.run_install(b).reason, "checksum mismatch")
        self.assertFalse(os.path.exists(self.dest()))

    def test_req_19_checksum_is_compared_before_the_file_is_in_place(self):
        seen = []
        orig = standalone._finalize
        standalone._finalize = lambda tmp, dest, plat: seen.append(os.path.exists(dest)) or orig(tmp, dest, plat)
        self.addCleanup(setattr, standalone, "_finalize", orig)
        self.assertIsNone(self.run_install(bodies_for("snyk-linux")))
        self.assertEqual(seen, [False])

    # REQ-21 (path logic; REQ-20 is covered in test_cli)
    def test_req_21_windows_destination_and_asset(self):
        r = self.run_install(bodies_for("snyk-win.exe"), platform="win32", machine="AMD64")
        if os.name == "nt":
            self.assertIsNone(r)
            self.assertTrue(os.path.isfile(self.dest("win32")))
        self.assertTrue(self.dest("win32").endswith("snyk-scan-plugin\\bin\\snyk.exe"))
        self.assertTrue(any(u.endswith("/snyk-win.exe") for u in self.op.requested))

    # REQ-22
    def test_req_22_no_matching_asset(self):
        r = self.run_install(bodies_for("snyk-linux"), machine="riscv64")
        self.assertTrue(r.reason.startswith("no standalone binary available: "), r.reason)
        rel = json.loads(RELEASE)
        del rel["assets"]["snyk-linux"]
        r = self.run_install(bodies_for("snyk-linux", release=json.dumps(rel)))
        self.assertTrue(r.reason.startswith("no standalone binary available: "), r.reason)
        self.assertIn("snyk-linux", r.reason)

    def test_req_22_release_json_unreachable_or_unparseable(self):
        r = self.run_install({})
        self.assertTrue(r.reason.startswith("no standalone binary available: "), r.reason)
        for junk in ["not json", "[]", '{"assets": 5}', '{"assets": {"snyk-linux": {"url": 3}}}']:
            r = self.run_install({standalone.RELEASE_URL: junk})
            self.assertTrue(r.reason.startswith("no standalone binary available: "), (junk, r.reason))

    def test_req_22_download_failure_is_reported(self):
        b = bodies_for("snyk-linux")
        del b[json.loads(RELEASE)["assets"]["snyk-linux"]["url"]]
        r = self.run_install(b)
        self.assertIn("download failed", r.reason)
        self.assertFalse(os.path.exists(self.dest()))

    def test_req_22_install_standalone_can_be_disabled(self):
        from lib import install
        f = install.install_standalone(env={"SNYK_SCAN_PLUGIN_NO_STANDALONE": "1"})
        self.assertIn("disabled", f.reason)


if __name__ == "__main__":
    unittest.main()
