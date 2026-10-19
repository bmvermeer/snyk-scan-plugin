# Plan: Snyk Scan Plugin

Spec: specs/spec.md (draft v2; continuation to plan requested 2026-10-15)

## Approach
Two thin Python entry points (`snapshot.py`, `scan.py`) call a small library of single-purpose modules. All logic is pure functions over explicit inputs (paths, env, a command runner), so it is testable against a stubbed `snyk` without a Claude runtime. Python 3 standard library only, so there is nothing to install beyond Python itself.

Approvals cannot be asked by a hook. When a scan needs an approval (install or `snyk auth`), `scan.py` continues the turn once with an instruction for Claude to ask the user. After approval Claude runs `hooks/helper.py <install|auth|decline>`, which does the work and records the outcome in session state. This keeps all prompting in conversation and all side effects in tested code.

Alternatives rejected: bash plus PowerShell (double the code and tests), a precompiled helper (build and release pipeline, new binary to trust).

## Components and interfaces
- `hooks/snapshot.py` (`UserPromptSubmit`): take the baseline, save to state. No output.
- `hooks/scan.py` (`Stop`): load baseline, diff, decide scans, run them, build the report, return the hook result (end turn or continue). Exits quietly when nothing changed.
- `hooks/helper.py`: subcommands `install`, `auth`, `decline <install|auth>`, `set-mode <mode>`. Called by Claude after approval and by the commands.
- `hooks/lib/files.py`: classify a path as source, dependency file, or neither (REQ-1, 2, 5, 6; extension list lives here and in the spec).
- `hooks/lib/baseline.py`: list files (git-aware with fallback list), hash, diff (REQ-7, 8, 10).
- `hooks/lib/state.py`: per-session JSON in the OS temp dir keyed by session ID; flags `install_declined`, `auth_declined`, `hint_shown`, `rescan_done` (REQ-9, 13, 25, 35).
- `hooks/lib/config.py`: read `.claude/snyk-plugin.json`, validate, fall back to `report` with a warning (REQ-35, 42, 48, 49).
- `hooks/lib/cli.py`: locate `snyk` (PATH, then standalone path), run with list arguments and a timeout, map exit codes and known error strings (REQ-20, 21, 27 to 33).
- `hooks/lib/install.py`: npm, brew, standalone download with host restriction and SHA-256 check, Alpine detection (REQ-14 to 22).
- `hooks/lib/report.py`: parse the CLI JSON, apply the threshold, rank, format summary lines, wrap output as untrusted data (REQ-31 to 34, 36, 37).
- `commands/snyk-mode.md`, `commands/snyk-scan.md`, `skills/snyk-scan/SKILL.md` (how Claude summarises, suggests, and applies fixes within REQ-39).
- `.claude-plugin/plugin.json` (version `0.1.0`), `hooks/hooks.json`, `LICENSE` (MIT), `README.md`, `CLAUDE.md`, `.github/workflows/test.yml`.

## T1 spike note: hook runtime contract (2026-10-15)
Sources: code.claude.com hooks and plugins-reference docs, plus a real headless run (`claude -p`, `--plugin-dir`, throwaway plugin outside the repo) on macOS, Python 3.9.6. **Windows run still pending**, so T1 is not done.

Verified on macOS:
- **Input** (JSON on stdin): `session_id`, `cwd`, `transcript_path`, `hook_event_name`, `permission_mode`. `Stop` adds `stop_hook_active`, `last_assistant_message`. `UserPromptSubmit` adds `prompt`. The process cwd equals `cwd`. `CLAUDE_PLUGIN_ROOT` and `CLAUDE_PROJECT_DIR` are set in the hook's environment.
- **Continue a turn:** `Stop` prints `{"decision":"block","reason":"..."}` (or exits 2). Claude receives `reason` as its next instruction and answered it.
- **Detect our own continuation:** `stop_hook_active` is `true` on the `Stop` that follows a block. Use it for REQ-11. Claude Code caps consecutive continuations at 8 (resets on a tool call).
- **`UserPromptSubmit` does not fire on a continuation.** The baseline is therefore not refreshed between the first `Stop` and the continuation's `Stop`. T8 must handle this: edits made during an `autofix` continuation look like changes against the old baseline, so `scan.py` must re-baseline itself (REQ-10) and use `stop_hook_active` to skip diff-triggered scans.
- **Show a message and end the turn:** `{"systemMessage":"..."}` with exit 0 appears as an informational line ("Stop says: ..."). Plain stdout of a successful `Stop` hook goes to the debug log only, so `report` mode must use `systemMessage`. `UserPromptSubmit` stdout is added as context for Claude, so `snapshot.py` must print nothing.
- **Plugin layout:** `hooks/hooks.json` has a top-level `"hooks"` key (matches plan). `${CLAUDE_PLUGIN_ROOT}` resolves in `command`. `.claude-plugin/plugin.json` needs only `name`. Plugin names starting with `claude-` are rejected (ours is `snyk-scan-plugin`, fine).
- **Launcher on macOS:** shell form `python3 "$SCRIPT" || python "$SCRIPT" || py -3 "$SCRIPT"` works (first entry matched).

Unverified, needs a Windows machine:
- Shell form runs under Git Bash, or PowerShell if Git Bash is absent. `||` chaining fails in Windows PowerShell 5.1, so the chain above may not work there. Candidate fixes: a `"shell":"bash"` hook plus the REQ-45 message when it is missing, or a tiny launcher that PowerShell and bash both parse. Exec form (`args`) needs a real `.exe`, so `command:"python"` or `"py"` works on Windows only, and `hooks.json` is one file for all OSes.
- REQ-45 message path when no Python exists.

Spec impact: none yet that contradicts a REQ. Additions needed: REQ-11 detection uses `stop_hook_active` and the no-`UserPromptSubmit`-on-continuation fact (clarify in T8), and the minimum Python is 3.9 (stdlib only, avoid 3.10+ syntax such as `match` and `X | Y` types). Resolve the open "Python launcher" question after the Windows run.

### T1 cross-check against the implementation (written retroactively, 2026-10-16)
Not from a fresh run. Re-read `hooks/hooks.json`, `hooks/scan.py`, `hooks/snapshot.py` against the note above; the macOS facts match the code:
- `snapshot.py` reads `session_id` and `cwd` from stdin JSON and prints nothing. `scan.py` reads the same, checks `stop_hook_active` for REQ-11, ends the turn with `{"systemMessage"}` and continues with `{"decision":"block","reason"}`.
- `hooks.json` launcher is the T13 form (`"shell":"bash"`, probe python3, python, `py -3`, REQ-45 message, exit 0). This supersedes the earlier `||` candidate in the verified list.
- Mismatch to resolve: the note's "Windows runs Git Bash, or PowerShell if absent" is from docs only, and `hooks.json` pins `bash`. Whether `"shell":"bash"` works on a Windows machine without Git Bash is unverified. No spec REQ is contradicted, but REQ-44 and REQ-45 are untested on real Windows.
- Remaining for T1: a real Windows run (shell, launcher, REQ-45 path).

### T13 launcher decision (2026-10-15, macOS only, Windows UNVERIFIED)
- Both hooks use `"shell": "bash"` with one sh command: loop over `python3`, `python`, `"py -3"`, run a probe (`import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)`), `exec` the first that passes, else print `{"systemMessage":"Snyk scan plugin: Python 3.9 or newer is required but was not found, so scans are off. ..."}` and `exit 0` (REQ-45; exit 2 would block). The probe also skips Python 2 and the Windows Store stub (exit 9009). Tested with `sh -c` and a PATH without Python (`tests/test_launcher.py`).
- Trade-off: PowerShell 5.1 cannot parse this (`||`, `for ... do ... done`), so rather than a second PowerShell form we pin `bash`. Claude Code on Windows normally has Git Bash. If it is absent, the hook cannot start; Claude Code reports that as a non-blocking hook error and no scan runs. Not verified. Alternative if the CI/manual run shows this matters: add a second hook entry with `"shell": "powershell"` (`if (Get-Command python3 ...)` form) and have each entry no-op under the wrong shell.
- Same issue for the Bash tool commands in `commands/*.md` and the helper commands in approval prompts: they assume a bash-style tool. Helper paths use forward slashes on Windows. If Claude uses its PowerShell tool instead, a quoted exe path needs `&` and may fail. Unverified.

## Parked: Windows (2026-10-19)
Windows verification is future work. Nothing is removed: T1's Windows run, T13, the Windows CI job, the `.cmd` stubs, and the launcher notes above stay as the starting point. 0.1.0 targets macOS and Linux. Open for the follow-up: bash launcher without Git Bash, a PowerShell hook entry, REQ-4 timing (0.696s on the Windows runner), and `commands/*.md` under a non-bash tool.

## Data model
- Baseline: `{ "<relative path>": "<sha256>" }`, stored with the session state.
- State file: `{ baseline, install_declined, auth_declined, hint_shown, rescan_done, pending: null|"install"|"auth" }`.
- Config: `{ "mode": "report|suggest|autofix", "severityThreshold": "low|medium|high|critical", "timeoutSeconds": int }`. Unknown keys ignored, unknown mode falls back to `report`.
- Finding (internal): `{ scan, severity, id, title, file, line, package, fixedIn }`. Only structured fields drive `autofix`.

## Order and parallelism
1. T1 spike first: it settles runtime facts everything else depends on.
2. T2 scaffold, then T3 to T6 libraries (T3, T4, T5 can run in parallel after T2).
3. T7 and T8 wire the hooks. Checkpoint: modes work end to end against the stub, on the developer's OS.
4. T9 to T11 install and auth (T9 and T10 sequential, T11 parallel to them).
5. T12 commands, T13 Windows parity, T14 CI, T15 README, T16 CLAUDE.md, T17 manual end-to-end. T14 should land early if the repo exists (see risk R5).

## Dependencies
- Python 3 (required at runtime), standard library only.
- Snyk CLI, `npm`, `brew`, `git` (optional): external, invoked, not bundled.
- Dev: `unittest` (standard library). A linter such as `ruff` would be a new dependency and needs approval before use in CI.

## Risks and mitigations
- R1: Claude's hook contract is not verified here (how a hook ends or continues a turn, how it reads the session ID, how a continuation is detected, where messages are shown, which shell runs the command on Windows). -> T1 spike confirms it against the current docs and a real run before any other work; unknowns change the spec first.
- R2: Python launcher differs per OS (`python3`, `python`, `py -3`). -> T1 picks one command form that works on all three, with the REQ-45 message as the fallback.
- R3: CLI error strings for auth and Snyk Code disabled may change. -> Isolate them in one table in `cli.py`; unrecognised errors take the generic REQ-28 path.
- R4: Baseline hashing may exceed 500 ms on large trees. -> Cache by size and mtime, hash only when those change; benchmark test at 10,000 files (REQ-4).
- R5: GitHub Actions needs a remote. -> Resolved: the remote exists at https://github.com/bmvermeer/snyk-scan-plugin. Everything (code, tests, `specs/`) is in that one repo. Remaining: confirm the workflow runs green (T14).
- R6: REQ-43 versus the approval prompt both continue or end turns. -> Spec amended: one allowed continuation for approvals.
- R7: Full scan output passed to Claude is a prompt-injection path (accepted decision). -> REQ-34 marking plus REQ-39 location limit, tested with a hostile fixture.

## Requirement coverage
| REQ | Covered by | Verified by |
|-----|------------|-------------|
| REQ-1 | files.py, scan.py | `test_req_01_source_extensions`, `test_req_01_source_change_runs_sast_once` |
| REQ-2 | files.py, scan.py, cli.py | `test_req_02_dependency_names`, `test_req_02_dependency_change_runs_sca_all_projects` |
| REQ-3 | baseline.py, scan.py | `test_req_03_no_change_is_empty`, `test_req_03_no_change_silent` |
| REQ-4 | baseline.py | `test_req_04_overhead_under_500ms_10k_files`, `test_req_04_git_repo_10k_files` |
| REQ-5 | scan.py | `test_req_05_deps_only_no_sast` |
| REQ-6 | scan.py | `test_req_06_source_only_no_sca` |
| REQ-7 | baseline.py | `test_req_07_fallback_exclusions`, `test_req_07_git_tracked_and_untracked_not_ignored` |
| REQ-8 | baseline.py, scan.py | `test_req_08_missing_baseline` |
| REQ-9 | state.py | `test_req_09_state_in_temp_not_project`, `test_req_09_snapshot_silent_and_writes_only_temp` |
| REQ-10 | scan.py, baseline.py | `test_req_10_11_40_no_loop_under_autofix`, `test_req_10_rebaseline_even_without_snapshot` |
| REQ-11 | scan.py | `test_req_11_unknown_active_stop_scans_nothing`, `test_req_11_no_scan_on_own_continuation` |
| REQ-12 | scan.py, helper.py | `test_req_12_missing_cli_continues_turn_to_ask_and_installs_nothing`, `test_req_12_reason_embeds_absolute_helper_commands` |
| REQ-13 | state.py, helper.py | `test_req_13_install_declined_skips_and_is_not_asked_again`, `test_req_13_declined_state_survives_new_turn` |
| REQ-14 | install.py | `test_req_14_approval_runs_npm_first_and_retries_scan`, `test_req_14_retry_reports_findings_as_untrusted` |
| REQ-15 | install.py | `test_req_15_npm_failure_falls_back_to_brew`, `test_req_15_npm_missing_falls_back_to_brew` |
| REQ-16 | install.py | `test_req_16_npm_and_brew_fail_then_standalone_is_installed_and_runs`, `test_req_16_checksum_mismatch_in_chain_is_a_listed_failure` |
| REQ-17 | install.py | `test_req_17_all_failures_listed_and_scan_skipped`, `test_req_17_failed_install_is_not_asked_again` |
| REQ-18 | install.py | `test_req_18_asset_selection_per_os_and_cpu`, `test_req_18_alpine_detection` |
| REQ-19 | install.py | `test_req_19_checksum_mismatch_deletes_file`, `test_req_19_mismatch_keeps_an_existing_good_install` |
| REQ-20 | cli.py, install.py | `test_req_20_standalone_path_posix`, `test_req_20_finds_on_path` |
| REQ-21 | cli.py, install.py | `test_req_21_standalone_path_windows`, `test_req_21_finds_standalone_without_path_windows` |
| REQ-22 | install.py | `test_req_22_no_matching_asset`, `test_req_22_release_json_unreachable_or_unparseable` |
| REQ-23 | cli.py, scan.py | `test_req_23_not_authenticated_continues_turn_to_ask_and_runs_no_auth`, `test_req_23_reason_embeds_absolute_helper_commands` |
| REQ-24 | helper.py, cli.py | `test_req_24_approval_runs_auth_then_retries_scan_once`, `test_req_24_retry_reports_findings_as_untrusted` |
| REQ-25 | helper.py, state.py | `test_req_25_decline_names_reason_and_is_not_asked_again`, `test_req_25_declined_state_survives_new_turn` |
| REQ-26 | all modules | `test_req_26_token_not_echoed_or_passed_on_the_command_line`, `test_req_26_source_does_not_touch_token_or_auth_config` |
| REQ-27 | cli.py, scan.py | `test_req_27_known_code_disabled_strings`, `test_req_27_code_disabled_only_for_sast` |
| REQ-28 | cli.py | `test_req_28_unknown_error_first_line`, `test_req_28_unknown_error_no_text` |
| REQ-29 | cli.py | `test_req_29_timeout_kills_and_reports`, `test_req_29_timed_out` |
| REQ-30 | cli.py, report.py | `test_req_30_exit_2_failed`, `test_req_30_exit_3_nothing_to_scan` |
| REQ-31 | report.py | `test_req_31_sast_no_issues`, `test_req_31_sca_no_issues` |
| REQ-32 | report.py | `test_req_32_all_below_threshold`, `test_req_32_sast_below_threshold` |
| REQ-33 | cli.py | `test_req_33_args_are_lists`, `test_req_33_no_shell` |
| REQ-34 | report.py | `test_req_34_hostile_sast`, `test_req_34_hostile_sca` |
| REQ-35 | config.py, state.py | `test_req_35_default_report_no_file`, `test_req_35_hint_once_per_session_without_config` |
| REQ-36 | report.py, scan.py | `test_req_36_counts_by_severity`, `test_req_36_top_5_ranked` |
| REQ-37 | report.py, scan.py | `test_req_37_suggest_continues_with_summary_and_no_edit_instruction`, `test_req_37_suggest_continuation_runs_nothing` |
| REQ-38 | scan.py, SKILL.md | `test_req_38_autofix_continues_with_full_output_as_untrusted_data`, `test_req_38_autofix_hostile_output_cannot_close_wrapper` |
| REQ-39 | SKILL.md, report.py | `test_req_39_autofix_instruction_limits_edits_to_named_locations` |
| REQ-40 | scan.py | `test_req_40_rescan_only_scans_that_had_findings` |
| REQ-41 | report.py | `test_req_41_fixed_and_remaining`, `test_req_41_reports_fixed_and_remaining` |
| REQ-42 | config.py | `test_req_42_broken_json`, `test_req_42_unknown_mode` |
| REQ-43 | scan.py | `test_req_43_failed_scan_never_continues_in_suggest_or_autofix`, `test_req_43_timeout_never_continues_in_autofix` |
| REQ-44 | all modules, CI | `test_req_44_which_ignores_cwd_on_windows`, `test_req_44_which_skips_relative_path_entries_on_windows` |
| REQ-45 | hooks.json launcher | `test_req_45_python_missing_message`, `test_req_45_unusable_python_is_skipped` |
| REQ-46 | helper.py, snyk-mode.md | `test_req_46_valid_mode_creates_config_and_dir`, `test_req_46_preserves_other_keys` |
| REQ-47 | scan.py, snyk-scan.md | `test_req_47_scan_runs_both_without_changes`, `test_req_47_scan_reports_findings_as_untrusted` |
| REQ-48 | config.py, cli.py | `test_req_48_timeout` |
| REQ-49 | config.py, report.py | `test_req_49_threshold`, `test_req_49_threshold_excludes_lower` |
| REQ-50 | commands/snyk-mode.md, helper.py, config.py | `test_req_50_get_config_defaults`, `test_req_50_get_config_shows_current_values` |
| REQ-51 | helper.py (cmd_scan), report.py | `test_req_51_scan_states_mode_and_snyk_mode_every_run`, `test_req_51_scan_shows_configured_mode_and_runs_same_scans` |
