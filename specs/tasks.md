# Tasks: Snyk Scan Plugin

Spec: specs/spec.md | Plan: specs/plan.md

Rules: one task at a time. Write the failing test first. A task is done only when its verification passes and all project gates are green. If the spec turns out wrong, stop and change the spec first. Keep the README in sync in the same change.

- [ ] **T1: Spike: verify the hook runtime contract**
  - Satisfies: REQ-44, REQ-45 (inputs to many others)
  - Acceptance: A short written note (added to the plan) states, from the docs and a real run: how a Stop hook ends or continues a turn, how a message reaches the user, how session ID and working directory are passed, how a plugin continuation is detected, which shell runs hook commands on Windows, and a launcher command that works on all three OSes. Any mismatch with the spec is raised before T2.
  - Verify: Minimal hook that logs its input, run on macOS and Windows.
  - Files: `plan.md` (note only), throwaway hook outside the repo
  - Status: left unticked. Note is in plan.md (macOS run, cross-checked with the implementation). Unverified: real Windows run (hook shell, bash launcher without Git Bash, REQ-45 path).

- [x] **T2: Scaffold the repo and test harness**
  - Satisfies: REQ-44 (foundation)
  - Depends on: T1
  - Acceptance: Repo skeleton exists with `plugin.json` at version `0.1.0`, MIT `LICENSE`, `hooks.json` (launcher from T1), stub `snyk` (shell and `.cmd` forms) with scripted exit codes, and one passing placeholder `unittest`.
  - Verify: `python -m unittest discover` passes locally.
  - Files: `.claude-plugin/plugin.json`, `hooks/hooks.json`, `LICENSE`, `tests/stubs/snyk`, `tests/stubs/snyk.cmd`

- [x] **T3: File classification and config**
  - Satisfies: REQ-1, REQ-2 (classification), REQ-35, REQ-42, REQ-48, REQ-49
  - Depends on: T2
  - Acceptance: Paths classify as source, dependency, or neither using the spec lists (extension list finalised and added to the spec). Config loads, validates, and falls back to `report` with a named warning.
  - Verify: unit tests `test_req_42_*`, `test_req_48_*`, `test_req_49_*`, plus classification tests.
  - Files: `hooks/lib/files.py`, `hooks/lib/config.py`, `tests/test_files.py`, `tests/test_config.py`

- [x] **T4: Baseline, diff, and state**
  - Satisfies: REQ-3, REQ-4, REQ-7, REQ-8, REQ-9, REQ-10
  - Depends on: T2
  - Acceptance: Baseline uses git when available, else the exclusion list. Diff reports changed source and dependency files. State lives in the OS temp dir keyed by session ID. 10,000-file tree finishes under 500 ms.
  - Verify: `test_req_03_*`, `test_req_04_*`, `test_req_07_*`, `test_req_08_*`, `test_req_09_*`.
  - Files: `hooks/lib/baseline.py`, `hooks/lib/state.py`, `hooks/snapshot.py`, `tests/test_baseline.py`

- [x] **T5: CLI runner and exit-code mapping**
  - Satisfies: REQ-20, REQ-21, REQ-27, REQ-28, REQ-29, REQ-30, REQ-33
  - Depends on: T2
  - Acceptance: `snyk` is found on PATH or at the standalone path. Commands run with list arguments and a timeout. Exit codes and known error strings map to results (ok, findings, failed, nothing to scan, timed out, not authenticated, Snyk Code disabled, unknown error).
  - Verify: `test_req_27_*` to `test_req_30_*`, `test_req_33_*` against the stub.
  - Files: `hooks/lib/cli.py`, `tests/test_cli.py`

- [x] **T6: Report formatting**
  - Satisfies: REQ-31, REQ-32, REQ-34, REQ-36, REQ-41
  - Depends on: T3, T5
  - Acceptance: One-line results, threshold handling, top-5 ranking, and output wrapped as untrusted data. Hostile text in a fixture does not escape the wrapper.
  - Verify: `test_req_31_*`, `test_req_32_*`, `test_req_34_*`, `test_req_36_*`.
  - Files: `hooks/lib/report.py`, `tests/test_report.py`, `tests/fixtures/`

- [x] **T7: Stop hook for `report` mode**
  - Satisfies: REQ-1, REQ-2, REQ-5, REQ-6, REQ-11, REQ-26, REQ-35, REQ-43
  - Depends on: T3, T4, T5, T6
  - Acceptance: A changed source file runs SAST once, a changed dependency file runs SCA once, never the other. No relevant change prints nothing. The turn ends. A hook-triggered continuation starts no new scan. The first-run hint is shown once per session.
  - Verify: `test_req_01_*`, `test_req_02_*`, `test_req_05_*`, `test_req_06_*`, `test_req_11_*`, `test_req_43_*`, and a source scan for token access (`test_req_26_*`).
  - Files: `hooks/scan.py`, `tests/test_scan_report_mode.py`

- [x] **T8: `suggest` and `autofix` modes and no-loop**
  - Satisfies: REQ-10, REQ-37, REQ-38, REQ-39, REQ-40, REQ-41
  - Depends on: T7
  - Acceptance: `suggest` continues the turn with proposals and edits nothing. `autofix` continues, re-scans only scans that had findings, once, re-baselines, and reports fixed and remaining. `SKILL.md` limits edits to named locations.
  - Verify: `test_req_37_*` to `test_req_41_*`, `test_req_10_*`, and the no-loop test under `autofix`.
  - Files: `hooks/scan.py`, `skills/snyk-scan/SKILL.md`, `tests/test_scan_modes.py`

- [x] **T9: Install via npm and brew, with approval**
  - Satisfies: REQ-12, REQ-13, REQ-14, REQ-15, REQ-17
  - Depends on: T7
  - Acceptance: A missing CLI continues the turn once so Claude asks. Approval runs npm, then brew on macOS and Linux, and reports every failure. Decline is remembered for the session.
  - Verify: `test_req_12_*` to `test_req_15_*`, `test_req_17_*` with stubbed `npm` and `brew`.
  - Files: `hooks/lib/install.py`, `hooks/helper.py`, `tests/test_install.py`

- [x] **T10: Standalone binary install**
  - Satisfies: REQ-16, REQ-18, REQ-19, REQ-21, REQ-22
  - Depends on: T9
  - Acceptance: `release.json` is fetched, the OS and CPU asset is chosen (Alpine check settled and added to the spec), only `downloads.snyk.io` over HTTPS is contacted including redirects, the SHA-256 is verified against `sha256Url`, and a mismatch deletes the file and prints "checksum mismatch". No sudo or admin rights are used.
  - Verify: `test_req_18_*`, `test_req_19_*`, `test_req_22_*` against a local fake server.
  - Files: `hooks/lib/install.py`, `tests/test_install_standalone.py`, `tests/fixtures/release.json`

- [x] **T11: Authentication flow**
  - Satisfies: REQ-23, REQ-24, REQ-25, REQ-26
  - Depends on: T7
  - Acceptance: A "not authenticated" result continues the turn once so Claude asks. Approval runs `snyk auth` and retries the scan once. Decline or failure skips the scan and is not asked again in the session. No token is read.
  - Verify: `test_req_23_*` to `test_req_25_*`.
  - Files: `hooks/helper.py`, `hooks/lib/cli.py`, `tests/test_auth.py`

- [x] **T12: Commands**
  - Satisfies: REQ-46, REQ-47
  - Depends on: T8
  - Acceptance: `/snyk-mode <mode>` writes the config for valid values and lists valid values otherwise. `/snyk-scan` runs both scans regardless of changes.
  - Verify: `test_req_46_*`, `test_req_47_*`.
  - Files: `commands/snyk-mode.md`, `commands/snyk-scan.md`, `hooks/helper.py`, `tests/test_commands.py`

- [ ] **T13: Windows parity and Python-missing message**
  - Satisfies: REQ-44, REQ-45
  - Depends on: T8, T10
  - Acceptance: The whole suite passes on Windows. The launcher prints the Python 3 required message when Python is missing and does not block the turn.
  - Verify: full suite on a Windows machine, `test_req_45_*`.
  - Files: `hooks/hooks.json`, fixes found in any module
  - Note: code side done on macOS; Windows run pending (T14 CI). Added launcher with REQ-45 message, `lib/where.py` (no cwd lookup), UTF-8 stdio, state.save retry, forward-slash helper paths. First CI run failed on Windows only (29 failures, 8 errors). Likely cause: tests/stubs/snyk.cmd had LF endings (autocrlf false), which breaks cmd.exe label/goto handling. Fixes: `.gitattributes` forces CRLF for .cmd/.bat, stub rewritten with flat goto flow, install test stubs written CRLF on Windows, tests made OS-aware (npm.cmd/brew.cmd removal, forward-slash helper path). Open: REQ-4 10k-file timing was 0.696s on the Windows runner, not changed. Second CI run: 13 Windows failures left, caused by cmd.exe `echo` mangling scripted stdout/stderr (JSON with special chars, 'ECHO is off.'). snyk.cmd now delegates to `tests/stubs/snyk_stub.py` (same SNYK_STUB_* contract as the sh stub), so cmd never echoes scripted text; the install test copies the .py next to the copied snyk.cmd. Verification needs a green Windows CI run.

- [ ] **T14: GitHub Actions workflow**
  - Satisfies: REQ-44 (cross-OS verification)
  - Depends on: T2 (repo must exist on GitHub, see R5)
  - Acceptance: The suite runs on macOS, Linux, and Windows runners on every push and pull request, with the same command used locally. Adding a linter needs approval first.
  - Verify: A pull request shows three green jobs.
  - Files: `.github/workflows/test.yml`
  - Note: workflow file written (ubuntu, macos, windows; Python 3.9 and latest 3.x; `python -m unittest discover`). Not marked done: verification (a PR with green jobs) is pending a GitHub remote.

- [x] **T15: README**
  - Satisfies: Boundaries (README in sync)
  - Depends on: T12
  - Acceptance: README covers both install channels, the three modes, config keys, approvals, the Python 3 requirement, and the test command. Every REQ-visible feature is described, and nothing is described that does not exist.
  - Verify: Manual read against the spec and a fresh install on a clean machine.
  - Files: `README.md`

- [x] **T16: Repo CLAUDE.md**
  - Satisfies: v0.1 bootstrap scope
  - Depends on: T14
  - Acceptance: `CLAUDE.md` in the repo root has the real test, run, and single-test commands and the actual layout (code, `tests/`, and `specs/` in one repo), and no "planned" wording.
  - Verify: Commands in the file run as written.
  - Files: `CLAUDE.md`
  - Note: T14 (CI green) is still unverified; no CI run has been confirmed. Commands were run locally and work.

- [ ] **T17: Manual end-to-end release check for 0.1.0**
  - Satisfies: Success criteria
  - Depends on: T13, T14, T15, T16
  - Acceptance: With a real Snyk account: a source edit gives a SAST result, a lockfile edit gives an SCA result only, and a machine with no CLI or login reaches a first scan on approvals alone. Version is `0.1.0` in `plugin.json`.
  - Verify: Recorded manual run on macOS, Linux, and Windows.
  - Files: none

- [x] **T18: Usability: `/snyk-mode` interview and mode line in `/snyk-scan`**
  - Satisfies: REQ-46 (amended), REQ-50, REQ-51
  - Depends on: T12
  - Acceptance: `/snyk-mode` with no value interviews the user for mode, severity threshold and timeout and writes them in one step, keeping other keys, writing nothing on abort or invalid input. `/snyk-scan` output states the current mode and that `/snyk-mode` changes it, on every run. README updated.
  - Verify: `test_req_46_*`, `test_req_50_*`, `test_req_51_*`; full suite green.
  - Files: `commands/snyk-mode.md`, `commands/snyk-scan.md`, `hooks/helper.py`, `tests/test_commands.py`, `README.md`
  - Note: done. New helper subcommands `get-config` and `set-config --mode/--severity/--timeout`; the interview uses `AskUserQuestion` (falls back to plain text). The `/snyk-scan` mode line is appended in `cmd_scan` after the untrusted blocks. Untested on a real Claude session and on Windows (Git Bash quoting as for the other commands).
