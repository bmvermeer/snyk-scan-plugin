"""Helper that Claude runs after the user answers an approval question.

    helper.py [--session ID] [--project DIR] install
    helper.py [--session ID] [--project DIR] auth
    helper.py [--session ID] [--project DIR] decline <install|auth>

    helper.py [--session ID] [--project DIR] set-mode [report|suggest|autofix]   (/snyk-mode)
    helper.py [--session ID] [--project DIR] scan                                (/snyk-scan)

Output goes to stdout for Claude; it never raises.
"""
import argparse
import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scan as scan_hook  # noqa: E402
from lib import cli, config, install, report, state, stdio  # noqa: E402

DECLINE_KINDS = ("install", "auth")


def _retry_pending(st, project):
    """Retry the scans that were waiting for the CLI or a login (once)."""
    kinds = [k for k in (st.get("pending_scans") or []) if k in ("sast", "sca")]
    if not kinds:
        return []
    cfg = config.load(project)
    lines = ["Snyk scan results:"]
    for kind in kinds:
        res = cli.run_scan(kind, project, cfg.timeout_seconds)
        lines.append(report.format_scan(kind, res, cfg.severity_threshold))
    return lines + cfg.warnings


def cmd_install(args):
    st = state.load(args.session)
    if st["pending"] != "install":  # REQ-12: only after the approval question was asked
        return "No Snyk install is pending, nothing was installed."
    outcome = install.run_install()
    st["pending"] = None
    if outcome.ok:
        lines = ["Snyk CLI installed (%s)." % outcome.method]
        lines.extend(_retry_pending(st, args.project))
        st["pending_scans"] = None
    else:
        st["install_failed"] = True  # REQ-17: skip the scan, do not ask again this session
        st["pending_scans"] = None
        lines = [install.format_failures(outcome)]
    state.save(args.session, st)
    return "\n".join(lines)


def cmd_auth(args):
    st = state.load(args.session)
    if st["pending"] != "auth":  # REQ-23: only after the approval question was asked
        return "No Snyk authentication is pending, nothing was run."
    st["pending"] = None
    ok, reason = cli.run_auth(args.project)
    if ok:
        lines = ["Snyk authenticated."] + _retry_pending(st, args.project)  # REQ-24
        if any("not authenticated" in l for l in lines):
            st["auth_failed"] = True  # still no access: do not ask again
    else:
        st["auth_failed"] = True  # REQ-25: skip the scan, do not ask again this session
        lines = ["Snyk authentication failed: %s. Scans are skipped for this session." % reason]
    st["pending_scans"] = None
    state.save(args.session, st)
    return "\n".join(lines)


def cmd_decline(args):
    st = state.load(args.session)
    st["pending"] = None
    st["pending_scans"] = None
    if args.kind == "install":
        st["install_declined"] = True
        msg = "Snyk CLI install declined. Scans are skipped for this session."
    else:
        st["auth_declined"] = True
        msg = "Snyk authentication declined. Scans are skipped for this session (not authenticated)."
    state.save(args.session, st)
    return msg


def cmd_set_mode(args):
    """/snyk-mode (REQ-46). The only code that writes into the project (REQ-9).

    Invalid or missing value: nothing is written. A config file that is not a JSON
    object is never overwritten (REQ-42 spirit): the user fixes or removes it first.
    """
    valid = ", ".join(config.MODES)
    mode = args.mode
    if mode not in config.MODES:
        shown = "no mode given" if mode is None else "unknown mode %r" % mode
        return "%s. Valid modes: %s. %s is unchanged." % (shown, valid, config.CONFIG_PATH)
    path = os.path.join(args.project, config.CONFIG_PATH)
    data = {}
    if os.path.lexists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
        except (OSError, ValueError) as e:
            return ("%s exists but cannot be used (%s). It is unchanged, mode was not set. "
                    "Fix or delete the file, then run /snyk-mode again." % (config.CONFIG_PATH, e))
    data["mode"] = mode
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return "Snyk mode set to %s in %s." % (mode, config.CONFIG_PATH)


def cmd_scan(args):
    """/snyk-scan (REQ-47): both scans, whatever changed, same report path as the Stop hook.

    A command never continues the turn, so suggest and autofix print the same report as
    report mode. Session state is neither read nor written: the baseline, rescan_done,
    fix_pending and the asked-once flags stay as the hooks left them.
    """
    cfg = config.load(args.project)
    results = scan_hook.run_scans(types.SimpleNamespace(source=True, dependency=True),
                                  cfg, args.project)
    return scan_hook.build_message(results, cfg, False)


COMMANDS = {"install": cmd_install, "auth": cmd_auth, "decline": cmd_decline,
            "set-mode": cmd_set_mode, "scan": cmd_scan}


def build_parser():
    p = argparse.ArgumentParser(prog="helper.py")
    p.add_argument("--session", required=True)
    p.add_argument("--project", default=None)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("install")
    sub.add_parser("auth")
    d = sub.add_parser("decline")
    d.add_argument("kind", choices=DECLINE_KINDS)
    m = sub.add_parser("set-mode")
    m.add_argument("mode", nargs="?", default=None)
    sub.add_parser("scan")
    return p


def main(argv=None):
    stdio.use_utf8()
    args = build_parser().parse_args(argv)
    args.project = args.project or os.getcwd()
    try:
        print(COMMANDS[args.command](args))
    except Exception as e:
        print("Snyk helper error: %s" % str(e)[:200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
