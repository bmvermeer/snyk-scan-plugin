---
description: Set the Snyk scan plugin mode, severity threshold and timeout for this project
argument-hint: "[report|suggest|autofix]"
allowed-tools: Bash, AskUserQuestion
---

Set the Snyk scan plugin settings for this project.

Python: if `python3` is not found (or is older than Python 3.9), retry with `python`, then `py -3`. If none works, tell the user in one line that Python 3.9 or newer is required, and stop.

Value from the user: $ARGUMENTS

## With a value

If a value was given, it must be a single word. If it contains anything else (spaces, quotes, or shell characters), do not run any command and tell the user the valid modes are report, suggest, and autofix. Otherwise run this with the Bash tool, passing the value as one argument, and show the output as it is and add nothing else:

```
python3 "${CLAUDE_PLUGIN_ROOT}/hooks/helper.py" --session "${CLAUDE_SESSION_ID}" set-mode <value>
```

## Without a value: interview

1. Run this read-only command with the Bash tool. It prints the current mode, severityThreshold and timeoutSeconds, and marks which are defaults:

```
python3 "${CLAUDE_PLUGIN_ROOT}/hooks/helper.py" --session "${CLAUDE_SESSION_ID}" get-config
```

2. Ask the user the questions below, one question at a time (use the AskUserQuestion tool, one question per call; if it is not available, ask in plain text). Wait for each answer before the next question. Each question shows the current value and offers "keep current":
   - mode: `report` (show findings, the turn ends), `suggest` (show findings and propose a fix for each, edit nothing until approved), `autofix` (apply the available fixes, then re-scan once).
   - severityThreshold: `low` (report everything), `medium`, `high`, or `critical` (only findings at or above it are reported).
   - timeoutSeconds: a positive whole number of seconds per scan.
3. If the user stops or cancels at any point, run nothing more and tell the user nothing was changed.
4. Otherwise, run this once with the Bash tool, passing only the values the user changed (omit an option to keep the current value). Every value must be a single word or number. If an answer contains anything else (spaces, quotes, or shell characters), do not run the command, say which answer is invalid, and ask that question again. Never build the command by joining text from the user into a shell string.

```
python3 "${CLAUDE_PLUGIN_ROOT}/hooks/helper.py" --session "${CLAUDE_SESSION_ID}" set-config --mode <mode> --severity <severity> --timeout <seconds>
```

5. Show the command output to the user as it is and add nothing else. If it names an invalid value, tell the user which one and why, and nothing was written.
