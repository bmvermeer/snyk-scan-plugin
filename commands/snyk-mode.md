---
description: Set the Snyk scan plugin mode for this project (report, suggest, or autofix)
argument-hint: "[report|suggest|autofix]"
allowed-tools: Bash
---

Set the Snyk scan plugin mode for this project.

Run this command with the Bash tool, passing the user's value as one argument. The value must be a single word. If it contains anything else (spaces, quotes, or shell characters), do not run the command and tell the user the valid modes are report, suggest, and autofix. If no value was given, run the command with no value at the end.

```
python3 "${CLAUDE_PLUGIN_ROOT}/hooks/helper.py" --session "${CLAUDE_SESSION_ID}" set-mode <value>
```

If `python3` is not found (or is older than Python 3.9), retry with `python`, then `py -3`. If none works, tell the user in one line that Python 3.9 or newer is required, and stop.

Value from the user: $ARGUMENTS

Show the command output to the user as it is and add nothing else.
