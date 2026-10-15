"""UserPromptSubmit hook: record the file baseline for this turn. Prints nothing, never blocks."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import baseline, state, stdio  # noqa: E402


def main():
    stdio.use_utf8()
    try:
        data = json.load(sys.stdin)
        session_id = data["session_id"]
        root = data.get("cwd") or os.getcwd()
        st = state.load(session_id)
        st["baseline"] = baseline.take(root, st["baseline"])
        st["rescan_done"] = False
        state.save(session_id, st)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
