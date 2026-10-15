"""Standalone Snyk CLI install (REQ-16, 18, 19, 20, 21, 22).

Fetches release.json from downloads.snyk.io, picks the asset for this OS and CPU,
downloads it to a temp name next to the final path, verifies SHA-256 against the
file at the asset's `sha256Url` (never the inline `sha256`), and only then renames
it into place. Every request, redirects included, must be HTTPS to exactly
`downloads.snyk.io`. No sudo, no PATH change. Never reads or logs the Snyk token.

The network is reached through an injectable opener (object with
`open(url, timeout)` returning a file-like). Production uses RestrictedOpener,
which enforces the host rule on the request and on every redirect.
"""
import collections
import hashlib
import json
import os
import platform as _platform
import re
import subprocess
import sys
import urllib.parse
import urllib.request

from . import cli

ALLOWED_HOST = "downloads.snyk.io"
RELEASE_URL = "https://downloads.snyk.io/cli/stable/release.json"
METHOD = "standalone binary"
MAX_REASON = 200
CHUNK = 1 << 20
MAX_JSON = 5 << 20

Failure = collections.namedtuple("Failure", "method reason")


def validate_url(url):
    """Return url if it is https to exactly downloads.snyk.io, else raise ValueError."""
    if not isinstance(url, str) or not url:
        raise ValueError("not a URL")
    if "\\" in url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("URL contains forbidden characters")
    parts = urllib.parse.urlsplit(url)
    # netloc must be the bare host: no userinfo, no port, no suffix tricks.
    if parts.scheme.lower() != "https" or parts.netloc.lower() != ALLOWED_HOST:
        raise ValueError("only https://%s is allowed" % ALLOWED_HOST)
    return url


class RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class RestrictedOpener:
    """Production opener: validates the request URL, every redirect, and the final URL."""

    def __init__(self):
        self._opener = urllib.request.build_opener(
            RestrictedRedirectHandler(), urllib.request.HTTPSHandler())

    def open(self, url, timeout=None):
        validate_url(url)
        resp = self._opener.open(url, timeout=timeout)
        try:
            validate_url(resp.geturl())
        except ValueError:
            resp.close()
            raise
        return resp


def asset_name(platform, machine, musl):
    """Release asset name for this OS and CPU, or None (REQ-18)."""
    m = (machine or "").lower()
    cpu = "x64" if m in ("x86_64", "amd64", "x64") else "arm64" if m in ("arm64", "aarch64") else None
    if platform.startswith("win"):
        return "snyk-win.exe"  # one Windows asset; arm64 Windows runs it emulated
    if cpu is None:
        return None
    suffix = "-arm64" if cpu == "arm64" else ""
    if platform.startswith("darwin"):
        return "snyk-macos" + suffix
    if platform.startswith("linux"):
        return ("snyk-alpine" if musl else "snyk-linux") + suffix
    return None


def is_musl(release_file="/etc/alpine-release", ldd_output=None):
    """Alpine/musl check: /etc/alpine-release exists, or `ldd --version` mentions musl."""
    if os.path.exists(release_file):
        return True
    if ldd_output is None:
        try:
            p = subprocess.run(["ldd", "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, universal_newlines=True, timeout=10, shell=False)
            ldd_output = p.stdout or ""
        except (OSError, subprocess.SubprocessError):
            ldd_output = ""
    return "musl" in ldd_output.lower()


def _read_all(opener, url, timeout, limit=MAX_JSON):
    with opener.open(url, timeout=timeout) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError("response too large")
    return data


def _find_asset(release_bytes, name):
    """Return (url, sha256Url) for the asset, or raise ValueError with a reason."""
    try:
        release = json.loads(release_bytes.decode("utf-8"))
    except ValueError as e:
        raise ValueError("release.json is not valid JSON")
    assets = release.get("assets") if isinstance(release, dict) else None
    if isinstance(assets, list):
        assets = {a.get("name"): a for a in assets if isinstance(a, dict)}
    if not isinstance(assets, dict):
        raise ValueError("release.json has no assets")
    asset = assets.get(name)
    if not isinstance(asset, dict):
        raise ValueError("release.json has no asset %s" % name)
    url, sum_url = asset.get("url"), asset.get("sha256Url")
    if not isinstance(url, str) or not isinstance(sum_url, str):
        raise ValueError("asset %s has no url or sha256Url" % name)
    validate_url(url)
    validate_url(sum_url)
    return url, sum_url


def _parse_checksum(data):
    tokens = data.decode("utf-8", "replace").split()
    if tokens and re.fullmatch(r"[0-9a-fA-F]{64}", tokens[0]):
        return tokens[0].lower()
    return None


def _finalize(tmp, dest, platform):
    if not platform.startswith("win"):
        os.chmod(tmp, 0o755)
    os.replace(tmp, dest)


def _fail(reason):
    return Failure(METHOD, str(reason)[:MAX_REASON])


def install(opener=None, platform=None, machine=None, musl=None, home=None, env=None, timeout=120):
    """Install the standalone binary. Returns None on success, else a Failure. Never raises."""
    platform = platform or sys.platform
    machine = machine if machine is not None else _platform.machine()
    opener = opener or RestrictedOpener()
    dest = cli.standalone_path(platform=platform, home=home, env=env)
    name = None
    try:
        if musl is None:
            musl = platform.startswith("linux") and is_musl()
        name = asset_name(platform, machine, musl)
        if name is None:
            return _fail("no standalone binary available: no asset for %s on %s" % (platform, machine or "unknown CPU"))
        try:
            url, sum_url = _find_asset(_read_all(opener, validate_url(RELEASE_URL), timeout), name)
        except ValueError as e:
            return _fail("no standalone binary available: %s" % e)
        except OSError as e:
            return _fail("no standalone binary available: release.json could not be fetched (%s)" % e)
        try:
            expected = _parse_checksum(_read_all(opener, sum_url, timeout))
        except (OSError, ValueError) as e:
            return _fail("download failed: checksum file could not be fetched (%s)" % e)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = "%s.part-%d" % (dest, os.getpid())
        try:
            digest = hashlib.sha256()
            try:
                with opener.open(url, timeout=timeout) as resp, open(tmp, "wb") as out:
                    while True:
                        chunk = resp.read(CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk)
                        out.write(chunk)
            except (OSError, ValueError) as e:
                return _fail("download failed: %s" % e)
            if expected is None or digest.hexdigest() != expected:
                return _fail("checksum mismatch")
            _finalize(tmp, dest, platform)
            tmp = None
            return None
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    except Exception as e:  # never let an install bug escape the hook
        return _fail("unexpected error: %s" % e)
