"""Install the Snyk CLI after the user approved it (REQ-12, 14, 15, 17).

Order: `npm install -g snyk`, then `brew install snyk-cli` (macOS and Linux only),
then the standalone binary (T10, see install_standalone). Every method that fails
is recorded, so the report can list each failure (REQ-17). Arguments are always
lists, never a shell string. Never reads or logs the Snyk token.
"""
import collections
import os
import subprocess
import sys

from . import cli, standalone, where

INSTALL_TIMEOUT = 600
MAX_REASON = 200

# method is the name shown to the user; ok means snyk is now usable.
Outcome = collections.namedtuple("Outcome", "ok method failures")
Failure = collections.namedtuple("Failure", "method reason")


def _reason(proc_or_text, code=None):
    text = proc_or_text if isinstance(proc_or_text, str) else ""
    for line in reversed(text.strip().splitlines()):
        if line.strip():
            return line.strip()[:MAX_REASON]
    return "exit code %s" % code if code is not None else "failed"


def _run(cmd, env, timeout):
    """Run an installer. Returns (ok, reason). Never raises."""
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True,
                              encoding="utf-8", errors="replace", shell=False,
                              env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "timed out after %d seconds" % timeout
    except OSError as e:
        return False, str(e)[:MAX_REASON]
    if proc.returncode == 0:
        return True, ""
    return False, _reason(proc.stderr or proc.stdout, proc.returncode)


def _try_tool(method, tool, args, env, timeout):
    """Run `tool args` if the tool exists. Returns None on success, else a Failure."""
    path = where.which(tool, path=(env or os.environ).get("PATH", os.defpath))
    if not path:
        return Failure(method, "%s is not available" % tool)
    ok, reason = _run([path] + args, env, timeout)
    if not ok:
        return Failure(method, reason)
    if not cli.find_snyk(env=env if env is not None else os.environ):
        return Failure(method, "installed, but snyk was not found afterwards "
                               "(the npm or brew bin directory may not be on PATH)")
    return None


def install_npm(env=None, timeout=INSTALL_TIMEOUT):
    return _try_tool("npm install -g snyk", "npm", ["install", "-g", "snyk"], env, timeout)


def install_brew(env=None, timeout=INSTALL_TIMEOUT):
    return _try_tool("brew install snyk-cli", "brew", ["install", "snyk-cli"], env, timeout)


def install_standalone(env=None, timeout=INSTALL_TIMEOUT):
    """Standalone binary fallback (REQ-16, 18, 19, 22). See lib/standalone.py."""
    env = os.environ if env is None else env
    if env.get("SNYK_SCAN_PLUGIN_NO_STANDALONE") == "1":  # lets tests skip the network
        return Failure("standalone binary", "disabled by SNYK_SCAN_PLUGIN_NO_STANDALONE")
    home = env.get("HOME") or env.get("USERPROFILE")
    f = standalone.install(home=home, env=env, timeout=min(timeout, 300))
    if f is not None:
        return Failure(f.method, f.reason)
    if not cli.find_snyk(env=env, home=home):
        return Failure("standalone binary", "installed, but snyk was not found afterwards")
    return None


def run_install(env=None, platform=None, timeout=INSTALL_TIMEOUT):
    """Try each install method in order. Returns an Outcome; never raises."""
    platform = platform or sys.platform
    methods = [install_npm]
    if not platform.startswith("win"):
        methods.append(install_brew)
    methods.append(install_standalone)
    failures = []
    for method in methods:
        try:
            failure = method(env=env, timeout=timeout)
        except Exception as e:  # a bug in one method must not hide the others
            failure = Failure(method.__name__, "unexpected error: %s" % str(e)[:MAX_REASON])
        if failure is None:
            return Outcome(True, method.__name__.replace("install_", ""), failures)
        failures.append(failure)
    return Outcome(False, None, failures)


def format_failures(outcome):
    lines = ["Snyk CLI install failed. Every method tried:"]
    lines.extend("- %s: %s" % (f.method, f.reason) for f in outcome.failures)
    lines.append("Scans are skipped. Install the CLI yourself (https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli).")
    return "\n".join(lines)
