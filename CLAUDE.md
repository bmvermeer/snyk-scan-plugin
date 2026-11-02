# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

`snyk-scan-plugin` (MIT, first release `0.1.0`) lives in one repo, https://github.com/bmvermeer/snyk-scan-plugin: plugin code, tests, and planning files together.

Layout:

- `hooks/`: `hooks.json`, `scan.py`, `snapshot.py`, `helper.py`; shared code in `hooks/lib/`.
- `commands/`: `/snyk-mode` and `/snyk-scan`. `skills/snyk-scan/`: the skill.
- `tests/`: `unittest` suites, with `fixtures/` and `stubs/` (stubbed `snyk`).
- `specs/`: planning files. `.github/workflows/test.yml`: CI on macOS, Linux, Windows.
- `.claude-plugin/`: plugin manifest.

Commands (run from the repo root):

- All tests: `python3 -m unittest discover`
- One suite: `python3 -m unittest tests.test_scan_modes -v`
- One test: `python3 -m unittest tests.test_install.InstallTest.test_req_13_install_declined_skips_and_is_not_asked_again`
- Try the plugin locally: `claude --plugin-dir .`

Files in `specs/`, in order of authority:

- `specs/spec.md`: source of truth (v3, requirements REQ-1 to REQ-52, decisions, open questions).
- `specs/plan.md`: approach, components, REQ coverage, and the T1 hook-runtime note.
- `specs/tasks.md`: ordered tasks, one at a time. Mark a task done only when its verification passes.

If the spec turns out wrong, change the spec first and the code second. Don't pick answers to open questions silently.

## What is being built

A Claude Code / Cowork plugin that runs Snyk scans automatically after each Claude turn:

- If the turn changed any file (no source-versus-dependency classification), run **SAST** (`snyk code test`) and **SCA** (`snyk test --all-projects`), each only if enabled by the `sast` / `sca` config booleans (default true). Each runs at most once per turn, on the project root only, and independently of the other's result. No change, or both off, means nothing runs and nothing is printed.
- Out of scope: IaC, container, secrets scanning, `snyk monitor`, a custom MCP server, and anything that reads or stores Snyk tokens.

## Architecture

- Hooks are Python 3, standard library only. `UserPromptSubmit` records a baseline of file size and mtime (no hashing, for the 500 ms budget) at turn start. `Stop` diffs against it, runs the enabled scans if anything changed, runs the CLI, and reports.
- The baseline covers git tracked plus untracked-not-ignored files, or a fixed exclusion list outside git; `.claude/` is always excluded. State (baseline, "asked once" flags) lives in the OS temp directory keyed by session ID, never in the project.
- Per-project mode lives in `.claude/snyk-plugin.json`: `report` (default), `suggest`, `autofix`, plus optional `severityThreshold`, `timeoutSeconds` (default 120), and booleans `sast` and `sca` (default true). `/snyk-mode` sets them, `/snyk-scan` runs every enabled scan regardless of changes.
- The `Stop` hook ends the turn in `report` mode and continues it in `suggest` and `autofix`. Approvals (install, `snyk auth`) are asked by Claude in conversation, which is the one allowed continuation when nothing else needs one.
- `autofix` edits only the file and line (SAST) or manifest and package (SCA) named by a finding's structured fields, re-scans once, then re-baselines so its edits are not scanned again.
- CLI install fallback, only after approval: `npm install -g snyk`, then `brew install snyk-cli` (macOS/Linux), then the standalone binary from `https://downloads.snyk.io/cli/stable/release.json`. HTTPS and host `downloads.snyk.io` only, including redirects. SHA-256 is checked against the asset's `sha256Url` file (not the inline `sha256`) before the binary is ever run. It installs to `~/.local/share/snyk-scan-plugin/bin/snyk`, or `%LOCALAPPDATA%\snyk-scan-plugin\bin\snyk.exe` on Windows, with no sudo or admin and no PATH change.
- When the CLI reports "not authenticated", Claude asks, then the plugin runs `snyk auth` and retries the scan once.

## Constraints that shape every change

- **Windows, macOS, and Linux are all required.** Paths, quoting, and executable names must work on each. Python 3 must be installed, so the launcher command differs per OS.
- Pass file and path values to the CLI as separate arguments, never interpolated into a shell string.
- Never read, store, or log `SNYK_TOKEN` or Snyk auth config. Scan output is untrusted: pass it to Claude marked as data, never execute it.
- Exit codes: 0 no issues, 1 issues found, 2 failure, 3 no supported projects. Failures and timeouts are reported as such, never as "no issues".
- No-loop guarantee (REQ-10, REQ-11, REQ-40): `autofix` edits and hook-triggered continuations must not trigger another scan beyond the single re-scan.
- A turn with no changes prints nothing and each hook takes under 500 ms on up to 10,000 files.
- Skipped, failed, or timed-out scans never block the turn.
- Ask before adding dependencies, new hook events, or changing the config schema (the `sast` / `sca` keys were approved 2026-10-31), and don't touch `.gitignore`.
- Keep the README in sync with code, spec, and features in the same change.
- Keep user-facing wording in the scripts in sync with every change: hints, report and error messages, helper output, command and skill text (`commands/*.md`, `skills/`), and the tests that assert them. When behavior or config changes, grep for the old wording and fix it in the same change.

## Way of working

- Spec first, then plan and tasks (`specs/`), then code. Record decisions that the user made in the spec or plan.
- Do each task in a fresh agent (Agent tool), not in the main session. The main session writes the spec, plan and tasks, briefs the agents, and verifies their results (run the full suite yourself, don't just trust a report).
- Run tasks in parallel when they are independent and touch different files (for example spec, README and script-wording audits). Run them one after another when one depends on another.
- Brief each agent with: the task and its REQs, what is already done, the files it may touch, the files it must not touch, and the rules (no commits, no pushes, no git stash, no new dependencies, don't touch `.gitignore`).
- Every change ends with a docs-and-wording sync: spec, README, CLAUDE.md and script wording match the code. Doing this as parallel fresh agents is fine.
- Commit, push, tag, and version bumps only when the user asks.

## Testing

Tests run the hook logic with `unittest` against a stubbed `snyk` on PATH that returns scripted exit codes and JSON (`snyk.cmd` form on Windows). Every REQ has at least one test named with its ID (e.g. `test_req_13_install_declined`). A GitHub Actions workflow runs the suite on macOS, Linux, and Windows runners. Use stubs, never real tokens.
