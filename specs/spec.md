# Project: Snyk Scan Plugin (SAST + SCA for Claude)

Status: v3, approved 2026-11-02 (v2 plus the 2026-10-31 change: any changed file triggers the enabled scans, `sast`/`sca` switches)
Owner: Brian Vermeer
Type: new greenfield project. One repository, `snyk-scan-plugin`, holds the code, tests, and these planning files (`specs/`).

## Problem
Developers using Claude to change code and dependencies get no automatic security feedback. Vulnerable code or packages can land in a project with no check. The Snyk CLI already does SAST (`snyk code test`) and SCA (`snyk test`), but nothing runs it at the moment Claude changes a project.

## Goals
- After every Claude turn that changes any file in the project, the enabled Snyk scans (SAST and SCA) run without the user asking.
- The user chooses, per project, what happens with results: report only, suggest fixes, or auto-fix.
- A user with no Snyk CLI installed, or not logged in, can go from zero to a first scan with only approvals, no manual setup.

## Non-goals
- IaC, container, and secrets scanning.
- `snyk monitor` and dashboard uploads.
- A custom MCP server.
- Reading, storing, logging, or minting Snyk tokens. (The CLI stores its own token; the plugin only starts `snyk auth`.)
- Scanning on every individual file edit or on commit/PR events.
- Updating, uninstalling, or re-checking the version of an installed CLI.
- Proxy, self-signed certificate, or offline support.

## Behavior
The plugin ships two hooks, both implemented in Python 3. `UserPromptSubmit` records a baseline of the project's files when a turn begins. `Stop` fires when Claude finishes the turn, compares the project to the baseline, runs SAST and SCA (each one unless switched off in config) if any file changed, then handles results according to the project's mode.

Mode is stored in `.claude/snyk-plugin.json` in the project and set with `/snyk-mode`. The `Stop` hook ends the turn in `report` mode and continues it in `suggest` and `autofix` so Claude can act on the results. Approvals (install, `snyk auth`) are asked by Claude in conversation, not by the hook.

### Scenarios
1. **Happy path:** Claude edits `app.js` and `package.json`. The turn ends. SAST and SCA each run once. Findings are summarised by severity and handled per mode.
2. **Invalid input:** `.claude/snyk-plugin.json` has broken JSON or an unknown mode. The plugin falls back to `report` and warns.
3. **Failure/timeout:** The CLI crashes, the network is down, or a scan exceeds the time limit. The user sees an explicit "scan failed" or "timed out" message, never "no issues".
4. **Not permitted:** The CLI is missing, the user is not authenticated, or Snyk Code is disabled for the org. Install and `snyk auth` need approval. If approval is declined, or the scan cannot proceed, the affected scan is skipped with an explanation and the turn is not blocked.
5. **Empty/boundary:** The turn changed nothing: no scan runs and nothing is printed. A turn that changed only a README runs both scans (any changed file triggers them). A project with no supported manifest reports "nothing to scan" for SCA. With `"sast": false` in config, only SCA runs.
6. **Autofix:** In `autofix` mode, Claude fixes findings, the affected scans re-run once, the result is reported, and the edits are not scanned again.

## Requirements
Levels: must blocks release; should and may do not.

### Triggering and change detection
- **REQ-1 (must):** Given a turn that changed at least one file and `sast` is enabled (REQ-52), when the turn ends, then `snyk code test` runs exactly once on the project root, whatever the file type.
- **REQ-2 (must):** Given a turn that changed at least one file and `sca` is enabled (REQ-52), when the turn ends, then `snyk test --all-projects` runs exactly once on the project root, whatever the file type. The two scans are independent: the result of one never decides whether the other runs (see REQ-27).
- **REQ-3 (must):** Given a turn that changed no files, when the turn ends, then no Snyk command runs and nothing is printed.
- **REQ-4 (must):** Given a turn that changed no files, when the `Stop` hook runs, then it completes in under 500 ms on a project of up to 10,000 files, and so does the `UserPromptSubmit` hook. Change detection compares file size and modification time only and never hashes content, so a file that was touched but is identical counts as a change.
- **REQ-5 (must):** Given `sast` is `false` in config, when the turn ends, then SAST does not run, whatever changed, and nothing is printed about it.
- **REQ-6 (must):** Given `sca` is `false` in config, when the turn ends, then SCA does not run, whatever changed, and nothing is printed about it. Given both are `false`, no Snyk command runs and nothing is printed.
- **REQ-7 (must):** Given the project is a git repo, when the baseline is taken, then it covers tracked files and untracked files that are not git-ignored, except anything under `.claude/` (so `/snyk-mode` config edits never trigger a scan). Given it is not a git repo, then it covers all files except `.claude`, `node_modules`, `.git`, `dist`, `build`, `target`, `venv`, `.venv`, `__pycache__`.
- **REQ-8 (must):** Given the `Stop` hook runs and no baseline exists for the session, when it runs, then no scan runs, nothing is printed, and a baseline is saved.
- **REQ-9 (must):** Given any run, when state is stored (baseline, "asked once" flags), then it is written to the OS temp directory under a file keyed by session ID, and nothing is written into the project except by `/snyk-mode`.
- **REQ-10 (must):** Given `autofix` finished its re-scan, when the turn ends, then a fresh baseline is saved so the autofix edits are not reported as changes in the next turn.
- **REQ-11 (must):** Given a turn continued by this plugin's own `Stop` hook, when it ends, then no scan runs except the single `autofix` re-scan of REQ-40.

### Install
- **REQ-12 (must):** Given `snyk` is neither on PATH nor at the standalone location (REQ-20, REQ-21), when a scan is due, then Claude asks the user for approval before installing, and nothing is installed without it.
- **REQ-13 (must):** Given the user declines the install, when a scan is due, then the scan is skipped with a one-line message and the plugin does not ask again in the same session.
- **REQ-14 (must):** Given the user approves the install, when installing, then the plugin first runs `npm install -g snyk`.
- **REQ-15 (must):** Given npm is unavailable or failed, when installing on macOS or Linux, then the plugin runs `brew install snyk-cli`.
- **REQ-16 (must):** Given npm and brew are unavailable or failed, when installing, then the plugin installs the standalone binary (REQ-18).
- **REQ-17 (must):** Given every available install method failed, when reporting, then the plugin lists each failure and skips the scan.
- **REQ-18 (must):** Given a standalone install, when installing, then the plugin fetches `https://downloads.snyk.io/cli/stable/release.json`, selects the asset for the detected OS and CPU (`snyk-macos`, `snyk-macos-arm64`, `snyk-linux`, `snyk-linux-arm64`, `snyk-alpine`, `snyk-alpine-arm64`, `snyk-win.exe`), downloads its `url`, and on macOS and Linux makes it executable. Every request, including redirects, must be HTTPS to host `downloads.snyk.io`, otherwise it is rejected.
- **REQ-19 (must):** Given a standalone binary was downloaded, when installing, then its SHA-256 is verified against the file at the asset's `sha256Url` (not the inline `sha256` field, which can be a placeholder). On mismatch the file is deleted, nothing is executed, and the user sees "checksum mismatch".
- **REQ-20 (must):** Given a standalone binary was installed on macOS or Linux, when any later scan is due, then the plugin finds it at `~/.local/share/snyk-scan-plugin/bin/snyk` without a PATH change, and installation needs no `sudo`.
- **REQ-21 (must):** Given a standalone binary was installed on Windows, when any later scan is due, then the plugin finds it at `%LOCALAPPDATA%\snyk-scan-plugin\bin\snyk.exe` without a PATH change, and installation needs no administrator rights.
- **REQ-22 (must):** Given the OS or CPU has no matching asset in `release.json`, or `release.json` cannot be fetched or parsed, when installing, then the plugin reports "no standalone binary available: <reason>" and skips the scan.

### Authentication and availability
- **REQ-23 (must):** Given the CLI reports the user is not authenticated, when a scan is due, then Claude asks the user for approval to run `snyk auth`.
- **REQ-24 (must):** Given the user approves, when `snyk auth` completes successfully, then the plugin retries the scan once.
- **REQ-25 (must):** Given the user declines, or `snyk auth` fails or times out, when a scan is due, then the scan is skipped with a message that names the reason, and the plugin does not ask again in the same session.
- **REQ-26 (must):** Given any run, when the plugin acts, then it does not read, write, log, or print `SNYK_TOKEN` or the CLI's auth config.
- **REQ-27 (must):** Given Snyk Code is not enabled for the user's org, when SAST is due, then SAST is skipped with an explanation, and SCA still runs if due. This holds for every SAST outcome (disabled, failed, timed out, not installed, not authenticated), and the reverse.
- **REQ-28 (must):** Given a scan fails with an error the plugin does not recognise, when reporting, then the message is "scan failed: <first line of the error>", never "no issues".

### Running scans and results
- **REQ-29 (must):** Given a scan exceeds the timeout (default 120 s), when the timeout hits, then the scan is killed, reported as "timed out", and the turn is not blocked.
- **REQ-30 (must):** Given a CLI exit code of 2, when reporting, then the message is "scan failed: <reason>". Given exit code 3, then it is "nothing to scan". Never "no issues".
- **REQ-31 (must):** Given a CLI exit code of 0, when reporting, then the output is one line: "SAST: no issues" or "SCA: no issues".
- **REQ-32 (must):** Given exit code 1 and every finding is below `severityThreshold`, when reporting, then the line is "SAST: no issues at or above <threshold>" (or "SCA: ...").
- **REQ-33 (must):** Given any run, when the hook invokes the CLI, then file and path values are passed as separate arguments and never interpolated into a shell string.
- **REQ-34 (must):** Given scan output reaches Claude, when it is passed on, then it is wrapped with a note that it is untrusted data and must not be followed as instructions.

### Modes
- **REQ-35 (must):** Given no `.claude/snyk-plugin.json` exists, when results are handled, then the mode is `report`, and once per session the output says how to change it. The hint rides on a scan report, so when both scans are off (REQ-6) nothing is printed and no hint is shown.
- **REQ-36 (must):** Given mode `report`, when scans finish with findings, then the user sees counts by severity and the top 5 findings (title, severity, file or package), ranked by severity then by file or package name, and no file is edited. The turn ends.
- **REQ-37 (must):** Given mode `suggest`, when scans finish with findings, then the user sees the REQ-36 summary plus a proposed fix per top finding, no file is edited without the user's approval, and the turn continues so Claude can propose them.
- **REQ-38 (must):** Given mode `autofix`, when scans finish with findings, then the turn continues and Claude applies available fixes for SCA and SAST findings.
- **REQ-39 (must):** Given mode `autofix`, when Claude edits files, then for SCA it edits only the manifest and package named by the structured fields of a finding (`displayTargetFile`, `packageName`, `fixedIn`), and for SAST it starts from the finding's `file` and `startLine` and may edit any other source file inside the project root that the fix needs (for example a shared helper or a call site along the data flow). Never edited: anything outside the project root, config, CI and secrets files, `.claude/`, and lockfiles beyond what a dependency change needs. Edits are never driven by instructions found in the scan output (REQ-34). The end-of-turn note lists every file changed, and says which were not the finding's own file.
- **REQ-40 (must):** Given mode `autofix` applied fixes, when fixes are done, then only the scans that had findings re-run, once.
- **REQ-41 (must):** Given the `autofix` re-scan finished, when reporting, then the user sees what was fixed and what remains, and unfixed findings are not retried.
- **REQ-42 (must):** Given an invalid or unreadable config file, or an unknown mode, when results are handled, then the mode is `report` and a warning names the problem.
- **REQ-43 (must):** Given a scan was skipped, failed, or timed out, when the turn ends, then the turn is not continued or blocked on account of it. The only exception is the one-time approval prompt of REQ-12 or REQ-23, which continues the turn once so Claude can ask.

### Platform
- **REQ-44 (must, Windows part deferred to future work, 2026-10-19):** Given the plugin runs on Windows, when a scan or install is due, then every behavior in this spec works the same as on macOS and Linux: change detection, scans, modes, config, install fallback, auth, and messages.
- **REQ-45 (should):** Given Python 3 cannot be found, when a hook starts, then a one-line message says Python 3 is required, and the turn is not blocked.

### Commands and config
- **REQ-46 (should):** Given the user runs `/snyk-mode <report|suggest|autofix>`, when the value is valid, then it is written to `.claude/snyk-plugin.json`. When invalid, the file is unchanged and valid values are listed. When no value is given, REQ-50 applies.
- **REQ-47 (should):** Given the user runs `/snyk-scan`, when it executes, then every enabled scan (REQ-52) runs regardless of detected changes. Both run by default. Given both are switched off, it runs nothing and says "No scans are enabled. Turn them on with /snyk-mode."
- **REQ-50 (should):** Given the user runs `/snyk-mode` with no value, when it executes, then Claude interviews the user, one question at a time, for `mode` (`report`, `suggest`, `autofix`), `severityThreshold` (`low`, `medium`, `high`, `critical`), `timeoutSeconds` (positive integer), `sast` (on or off), and `sca` (on or off). Each question shows the current value (the default when no config exists) and what the options mean, and the user can keep the current value. After the last answer the answers are written to `.claude/snyk-plugin.json` in one step, keeping any other keys already in the file. A value that fails validation is not written and the user is told which one and why. If the user stops before the end, nothing is written. The config schema gains `sast` and `sca` (REQ-52).
- **REQ-51 (should):** Given the user runs `/snyk-scan`, when the results are shown, then the output also states the current mode and which scans are on (SAST, SCA, or none), and says mode and scans can be changed with `/snyk-mode`. This is shown on every run, not once per session, and it does not change what the scan does in any mode (REQ-47).
- **REQ-52 (must):** Given `sast` and `sca` in `.claude/snyk-plugin.json`, when config is loaded, then each is a boolean that defaults to `true` when absent or when there is no config file. A non-boolean value is treated as `true` and a warning names the key. `/snyk-mode` can set both (REQ-46, REQ-50), and the helper's `get-config` reports them.
- **REQ-48 (should):** Given `timeoutSeconds` in config is a positive integer, when a scan runs, then it is the timeout instead of 120.
- **REQ-49 (may):** Given `severityThreshold` in config, when reporting, then findings below it are excluded. Default is `low` (everything reported).

## Constraints
- Security: the plugin never reads, stores, or logs `SNYK_TOKEN` or auth config. Scan output is untrusted text: it is never executed and is marked as data (REQ-34). `autofix` edits are limited as REQ-39 says: SCA only the named manifest and package, SAST the finding's file plus other project source files the fix needs, never config, CI, secrets or `.claude/`. Install and `snyk auth` need explicit approval.
- Integrity: the checksum comes from the same host as the binary, so it guards against corruption and tampering in transit, not a compromised `downloads.snyk.io`.
- Performance: no-change turns add under 500 ms (REQ-4). Scan timeout defaults to 120 s and is configurable.
- Compatibility: macOS and Linux for 0.1.0. Windows support is future work (code and CI work kept, verification parked, see Decisions). Snyk CLI current stable. Claude Cowork / Claude Code plugin format.
- Network: the binary fallback reaches only `downloads.snyk.io` over HTTPS.
- Dependencies: Python 3 (required). The Snyk CLI. For install: `npm`, `brew`, or a Python-based download plus SHA-256 via the Python standard library. Git is optional (REQ-7). Any extra tool needs approval.

## Technical context
- Stack: Claude plugin (manifest, hooks, commands, skill), hook scripts in Python 3 standard library only.
- Exit codes: `snyk` returns 0 (no issues), 1 (issues found), 2 (failure), 3 (no supported projects).
- No file classification: any added or modified file counts as a change. Which scans run is decided only by the `sast` and `sca` config values.
- Layout (one repo; code and planning files together):

```
snyk-scan-plugin/
  .claude-plugin/plugin.json
  hooks/hooks.json
  hooks/snapshot.py    # UserPromptSubmit baseline
  hooks/scan.py        # Stop: diff, scan, report
  hooks/helper.py      # install, auth, decline, set-mode, scan (called after approval and by commands)
  hooks/lib/           # baseline, state, config, cli, install, standalone, report, ...
  commands/snyk-mode.md
  commands/snyk-scan.md
  skills/snyk-scan/SKILL.md   # how to summarise, suggest, fix
  tests/               # unittest suite, stubs/ (snyk, snyk.cmd), fixtures/
  specs/               # spec.md, plan.md, tasks.md (these files)
  CLAUDE.md  README.md  LICENSE
```

## Testing strategy
Hook logic is tested against a stubbed `snyk` on PATH that returns scripted exit codes and JSON. Fixtures cover each REQ by ID (e.g. `req-13-install-declined`). Levels: unit for change detection, config parsing, and exit-code mapping; integration for hook-in-sandbox runs; one manual end-to-end run against a real Snyk account per release. Every REQ has at least one test named with its ID. Tests must cover REQ-10, REQ-11, and REQ-40 together as the no-loop case under `autofix`. A GitHub Actions workflow runs the full suite on macOS, Linux, and Windows runners on every push and pull request; the same suite is runnable locally with a single documented command. The stubbed `snyk` must exist in a native form for each (e.g. `snyk.cmd` on Windows).

## Boundaries
- Always: ask before installing anything or running `snyk auth`. Run scans against the project root only. Use stubs in tests, not real tokens.
- Always: keep the README in sync with the code and spec in the same change.
- Ask first: adding dependencies, new hook events, changing the config schema, new default behaviors.
- Never: read or log tokens, auto-install without approval, edit files in `report` or `suggest` mode without approval, scan outside the project root, contact a host other than `downloads.snyk.io` for downloads.

## Success criteria
- Editing any file in a project with the plugin installed produces a SAST result and an SCA result (each if enabled) at the end of the turn with no manual action.
- With `"sast": false`, the same edit produces an SCA result and no SAST result.
- On a machine with no CLI or no login, approvals alone lead to a working first scan.
- All must-level REQs have passing tests on macOS and Linux in GitHub Actions (Windows is future work), and the no-loop test passes under `autofix`.

## Open questions
- [ ] Python launcher: which command do the hooks call (`python3`, `python`, or `py -3`), and how is it chosen per OS? (plan)
- [x] Alpine/musl detection: on Linux the plugin uses `snyk-alpine*` when `/etc/alpine-release` exists or `ldd --version` output mentions `musl`, otherwise `snyk-linux*`. CPU: `x86_64`/`AMD64` is x64, `arm64`/`aarch64` is arm64, anything else has no asset (REQ-22). Windows uses `snyk-win.exe` for any CPU. (settled in T10)
- [ ] Exact CLI error strings that identify "not authenticated" and "Snyk Code not enabled". (plan)
- [x] Exact source-file extension list. (obsolete since 2026-10-31: files are no longer classified)
- [ ] Repo location (e.g. which GitHub org): TBD. Does not block the plan. (Brian)

## Decisions
- Hook language: Python 3, required.
- `Stop` hook continues the turn only in `suggest` and `autofix`.
- `autofix` covers SCA and SAST. Scan output is passed in full, marked as untrusted data, and edits are limited to locations named by structured fields.
- SCA uses `--all-projects`.
- Baseline: git-aware with a fallback exclusion list. State in the OS temp directory keyed by session ID.
- No loops: one re-scan, then re-baseline.
- Auth: ask, run `snyk auth`, retry once.
- First release version is 0.1 (written `0.1.0` in `plugin.json`). The plugin is versioned from the start.
- CI is a GitHub Actions workflow running the test suite on macOS, Linux, and Windows runners. (An earlier "no CI for now" was reversed.)
- v0.1 bootstrap scope: README, LICENSE, version in `plugin.json`, GitHub Actions CI, and a repo `CLAUDE.md` updated with real commands once code exists. The changelog is kept below from 0.1.1 on.
- A README ships in v1 and must stay in sync with the code, specs, and features. A change to a requirement, command, mode, or config key is not done until the README reflects it.
- One repository: code, tests, and planning files (`specs/`, plus the repo `CLAUDE.md`) all live in `snyk-scan-plugin`. There is no separate specs repo. Repo name is `snyk-scan-plugin`. License is MIT. Distribution is both the plugin marketplace and GitHub install.
- REQ-4 budget confirmed: under 500 ms for each hook on a project of up to 10,000 files.
- Defaults accepted: `severityThreshold` is `low`, no binary update checks in v1, the plugin does not touch `.gitignore`, and the user decides whether to commit `.claude/snyk-plugin.json`.

- Windows is parked as future work (2026-10-19). 0.1.0 is verified on macOS and Linux only. The Windows code, `.cmd` stubs, and the Windows CI job stay in the repo, but a green Windows run, the real Windows hook check (T1), and the REQ-4 Windows timing are not release gates. REQ-44, REQ-45, and REQ-21 stay as the target for the Windows follow-up.

## Assumptions
- Users have a Snyk account and a browser available for `snyk auth`. Headless sessions fall under REQ-25.
- Node/npm or Homebrew is available for install, or the standalone binary path is used.
- The plugin runtime supports `Stop` and `UserPromptSubmit` hooks that can read the working directory and can continue a turn.
- Python 3 is installed on user machines.
- "Cycle" means one Claude turn (confirmed).
- Windows on x64 uses `snyk-win.exe` (the only Windows asset in `release.json`); Windows on ARM runs it under emulation.

## Changelog
- **0.1.1 (2026-11-02):** any changed file triggers both scans (no source/dependency classification, REQ-1 to 6). Config switches `sast` and `sca`, default on (REQ-52), set through the `/snyk-mode` interview. `/snyk-scan` runs the enabled scans and says so when none are enabled (REQ-47). Baseline records size and mtime only, no hashing (REQ-4), and excludes `.claude/` (REQ-7). Snyk Code "not supported for your organization" is recognised as SAST disabled (REQ-27, SCA still runs). The real unauthenticated CLI message is matched exactly (REQ-23).
- **0.1.2 (2026-11-02):** REQ-39 widened for SAST (decision 2026-11-02): a deeper code problem can be fixed in other project files, with guardrails.
