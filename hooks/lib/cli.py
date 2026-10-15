"""Locate and run the Snyk CLI, and map its result (REQ-20, 21, 27 to 30, 33).

Never reads, stores, or logs the Snyk token or the CLI auth config (REQ-26).
Scan output is untrusted data; this module only classifies it.
"""
import collections
import os
import signal
import subprocess
import sys

from . import where

# Statuses
OK = "ok"
FINDINGS = "findings"
FAILED = "failed"
NOTHING_TO_SCAN = "nothing_to_scan"
TIMED_OUT = "timed_out"
NOT_AUTHENTICATED = "not_authenticated"
CODE_DISABLED = "code_disabled"
UNKNOWN_ERROR = "unknown_error"
NOT_INSTALLED = "not_installed"

# CLI error strings, matched case-insensitively as substrings of stdout+stderr.
# UNVERIFIED: written from knowledge of the real Snyk CLI, not checked against a
# live CLI (spec open question, risk R3). Unrecognised errors fall through to
# the generic "scan failed" path (REQ-28), so a wrong entry degrades safely.
AUTH_ERRORS = (
    "Authentication required",
    "SNYK-0005",
    "Authentication error",
    "MissingApiTokenError",
    "snyk auth",
)
CODE_DISABLED_ERRORS = (
    "Snyk Code is not enabled",
    "SNYK-CODE-0005",
    "Snyk Code is not supported for org",
)

MAX_MESSAGE = 200
AUTH_TIMEOUT = 300  # seconds: `snyk auth` waits for a browser login (REQ-25)

Result = collections.namedtuple("Result", "status exit_code stdout stderr message")


def standalone_path(platform=None, home=None, env=None):
    """Where the plugin installs the standalone binary (REQ-20, REQ-21)."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    if platform.startswith("win"):
        base = env.get("LOCALAPPDATA") or os.path.join(home or os.path.expanduser("~"), "AppData", "Local")
        import ntpath
        return ntpath.join(base, "snyk-scan-plugin", "bin", "snyk.exe")
    home = home or os.path.expanduser("~")
    return "/".join([home.rstrip("/"), ".local", "share", "snyk-scan-plugin", "bin", "snyk"])


def find_snyk(env=None, home=None):
    """Return the path to snyk (PATH first, then the standalone location) or None."""
    env = os.environ if env is None else env
    found = where.which("snyk", path=env.get("PATH", os.defpath))
    if found:
        return found
    candidate = standalone_path(home=home, env=env)
    if os.path.isfile(candidate) and (os.name == "nt" or os.access(candidate, os.X_OK)):
        return candidate
    return None


def build_command(snyk, kind):
    """Argument list for a scan. Values are separate args, never a shell string (REQ-33)."""
    if kind == "sast":
        return [snyk, "code", "test", "--json"]
    if kind == "sca":
        return [snyk, "test", "--all-projects", "--json"]
    raise ValueError("unknown scan kind: %r" % (kind,))


def taskkill_path(env=None):
    """Absolute taskkill.exe, so the project directory is never searched."""
    env = os.environ if env is None else env
    root = env.get("SystemRoot") or env.get("windir") or "C:\\Windows"
    return root.rstrip("\\/") + "\\System32\\taskkill.exe"


def _kill_tree(proc):
    try:
        if os.name == "nt":
            subprocess.run([taskkill_path(), "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _first_line(*texts):
    for text in texts:
        for line in (text or "").splitlines():
            line = line.strip()
            if line:
                return line[:MAX_MESSAGE]
    return ""


def _contains(table, text):
    low = text.lower()
    return any(s.lower() in low for s in table)


def classify(kind, exit_code, stdout, stderr):
    """Map an exit code and output to a Result."""
    if exit_code == 0:
        return Result(OK, 0, stdout, stderr, "")
    if exit_code == 1:
        return Result(FINDINGS, 1, stdout, stderr, "")
    if exit_code == 3:
        return Result(NOTHING_TO_SCAN, 3, stdout, stderr, "nothing to scan")
    combined = (stdout or "") + "\n" + (stderr or "")
    if _contains(AUTH_ERRORS, combined):
        return Result(NOT_AUTHENTICATED, exit_code, stdout, stderr, "not authenticated")
    if kind == "sast" and _contains(CODE_DISABLED_ERRORS, combined):
        return Result(CODE_DISABLED, exit_code, stdout, stderr,
                      "Snyk Code is not enabled for your organization")
    reason = _first_line(stderr, stdout) or "exit code %s" % exit_code
    status = FAILED if exit_code == 2 else UNKNOWN_ERROR
    return Result(status, exit_code, stdout, stderr, "scan failed: " + reason)


def run_scan(kind, cwd, timeout, env=None, home=None):
    """Run one scan ('sast' or 'sca') in cwd. Never raises for CLI problems."""
    snyk = find_snyk(env=env, home=home)
    if not snyk:
        return Result(NOT_INSTALLED, None, "", "", "snyk CLI not found")
    return run_command(build_command(snyk, kind), kind, cwd, timeout, env)


def run_command(cmd, kind, cwd, timeout, env=None):
    kwargs = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True  # own process group so children can be killed
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, encoding="utf-8", errors="replace",
                                shell=False, **kwargs)
    except OSError as e:
        return Result(UNKNOWN_ERROR, None, "", "", "scan failed: " + str(e)[:MAX_MESSAGE])
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass
        return Result(TIMED_OUT, None, "", "", "timed out")
    return classify(kind, proc.returncode, out, err)


def run_auth(cwd, timeout=AUTH_TIMEOUT, env=None, home=None):
    """Run `snyk auth` (REQ-24). Returns (ok, reason). Never raises.

    The CLI handles the login itself; this reads and passes on no credentials (REQ-26).
    """
    snyk = find_snyk(env=env, home=home)
    if not snyk:
        return False, "snyk CLI not found"
    res = run_command([snyk, "auth"], "auth", cwd, timeout, env)
    if res.status == OK:
        return True, ""
    if res.status == TIMED_OUT:
        return False, "timed out after %d seconds waiting for the login" % timeout
    reason = _first_line(res.stderr, res.stdout)
    if not reason:
        reason = res.message if res.exit_code is None else "exit code %s" % res.exit_code
    return False, reason
