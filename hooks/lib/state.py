"""Per-session state in the OS temp directory (REQ-9). Nothing is written into the project."""
import json
import os
import re
import tempfile
import time

DEFAULTS = {
    "baseline": None,
    "install_declined": False,
    "auth_declined": False,
    "auth_failed": False,
    "hint_shown": False,
    "rescan_done": False,
    "fix_pending": None,
    "pending": None,
    "pending_scans": None,
    "install_failed": False,
}


def path_for(session_id):
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(session_id))[:100] or "unknown"
    return os.path.join(tempfile.gettempdir(), "snyk-scan-plugin-%s.json" % safe)


def load(session_id):
    state = dict(DEFAULTS)
    try:
        with open(path_for(session_id), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            state.update({k: v for k, v in data.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    return state


def save(session_id, state):
    path = path_for(session_id)
    tmp = "%s.%d.tmp" % (path, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
        for attempt in range(5):  # Windows: the target may be open in another hook
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
