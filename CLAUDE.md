# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

Everything lives in this one repo: the plugin code (`hooks/`, `commands/`, `skills/`), the tests (`tests/`), and the planning files (`specs/`). There is no separate specs repo. Run the tests with `python3 -m unittest discover` (T16 finalises this section). The project is `snyk-scan-plugin` (MIT, first release `0.1.0`). Files in `specs/`, in order of authority:

- `specs/spec.md`: source of truth (draft v2, requirements REQ-1 to REQ-49, decisions, open questions).
- `specs/plan.md`: approach, components, REQ coverage, and the T1 hook-runtime note.
- `specs/tasks.md`: ordered tasks, one at a time. Mark a task done only when its verification passes.

If the spec turns out wrong, change the spec first and the code second. Don't pick answers to open questions silently. Once the real commands are final, replace this section (task T16).

## What is being built

A Claude Code / Cowork plugin that runs Snyk scans automatically after each Claude turn:

- **SAST** (`snyk code test`) if source files changed. **SCA** (`snyk test --all-projects`) if dependency manifests or lockfiles changed. Each runs at most once per turn, on the project root only. Neither runs if the turn changed nothing relevant.
- Out of scope: IaC, container, secrets scanning, `snyk monitor`, a custom MCP server, and anything that reads or stores Snyk tokens.

## Architecture

- Hooks are Python 3, standard library only. `UserPromptSubmit` records a baseline of file hashes at turn start. `Stop` diffs against it, decides which scans to run, runs the CLI, and reports.
- The baseline covers git tracked plus untracked-not-ignored files, or a fixed exclusion list outside git. State (baseline, "asked once" flags) lives in the OS temp directory keyed by session ID, never in the project.
- Per-project mode lives in `.claude/snyk-plugin.json`: `report` (default), `suggest`, `autofix`, plus optional `severityThreshold` and `timeoutSeconds` (default 120). `/snyk-mode` sets it, `/snyk-scan` forces both scans.
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
- A turn with no relevant changes prints nothing and each hook takes under 500 ms on up to 10,000 files.
- Skipped, failed, or timed-out scans never block the turn.
- Ask before adding dependencies, new hook events, or changing the config schema, and don't touch `.gitignore`.
- Keep the README in sync with code, spec, and features in the same change.

## Testing

Tests run the hook logic with `unittest` against a stubbed `snyk` on PATH that returns scripted exit codes and JSON (`snyk.cmd` form on Windows). Every REQ has at least one test named with its ID (e.g. `test_req_13_install_declined`). A GitHub Actions workflow runs the suite on macOS, Linux, and Windows runners. Use stubs, never real tokens.
