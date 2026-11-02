# snyk-scan-plugin

A Claude Code / Cowork plugin that runs Snyk scans automatically after each Claude turn.

- If the turn changed any file, whatever its type, both scans run:
  - **SAST** (`snyk code test`), unless `sast` is `false` in the config.
  - **SCA** (`snyk test --all-projects`), unless `sca` is `false` in the config.
- Each scan runs at most once per turn, on the project root only. The two scans are independent: one failing, timing out, or being skipped never stops the other. A turn that changed no files, or one where both scans are switched off, runs no scan and prints nothing.

Version `0.1.1`, MIT license. Status: published for end-to-end testing. The manual end-to-end run on macOS and Linux (task T17) is still pending. Windows support is future work and has not been verified on a real Windows machine (see [Known limitations](#known-limitations)).

Out of scope: IaC, container, and secrets scanning, `snyk monitor`, a custom MCP server, and anything that reads or stores Snyk tokens.

## Requirements

- **Python 3.9 or newer.** The hooks are Python 3, standard library only. The hook launcher tries `python3`, then `python`, then `py -3`, and uses the first one that is 3.9 or newer. If none is found, a one-line message says Python 3.9+ is required, scans are off, and the turn is not blocked.
- The **Snyk CLI**, or approval to install it (see [Approvals](#approvals)).
- A Snyk account for `snyk auth`.
- Git is optional (it only changes how files are listed, see [How it works](#how-it-works)).
- The hooks run through `bash` (`"shell": "bash"` in `hooks/hooks.json`). On Windows that means Git Bash must be available.

## Install

The repository <https://github.com/bmvermeer/snyk-scan-plugin> is both the plugin and its own marketplace (named `snyk-scan`).

- **From GitHub (recommended).** In a terminal, one step (the `--marketplace` option of `claude plugin install` adds the marketplace first if needed):

  ```
  claude plugin install snyk-scan-plugin --marketplace bmvermeer/snyk-scan-plugin
  ```

  Or in two steps, from a terminal or from inside Claude Code with a leading `/plugin`:

  ```
  claude plugin marketplace add bmvermeer/snyk-scan-plugin
  claude plugin install snyk-scan-plugin@snyk-scan
  ```

  Then restart Claude Code (or run `/reload-plugins` inside it). Verify that `/snyk-mode` is available.
- **Scope.** By default the plugin is installed for you in every project (`user`). To limit it to one folder, launch `claude` there and install with `--scope project` (writes `.claude/settings.json`, shareable) or `--scope local` (writes `.claude/settings.local.json`, only you):

  ```
  claude plugin install snyk-scan-plugin@snyk-scan --scope local
  ```

  The plugin scans the directory Claude was launched in, so launching from a monorepo subfolder scopes the scans to it.
- **Update.** Refresh the marketplace, update the plugin, then restart Claude Code:

  ```
  claude plugin marketplace update snyk-scan
  claude plugin update snyk-scan-plugin@snyk-scan
  ```

  Claude Code detects updates by the `version` in `.claude-plugin/plugin.json`, so a new release needs a version bump.
- **Uninstall.** Remove the plugin, and optionally the marketplace:

  ```
  claude plugin uninstall snyk-scan-plugin@snyk-scan
  claude plugin marketplace remove snyk-scan
  ```

  Add `--scope project` or `--scope local` if you installed with that scope. To reset the per-project mode, delete `.claude/snyk-plugin.json`.
- **Local checkout (development).** `claude --plugin-dir /path/to/snyk-scan-plugin` loads the plugin from a clone of this repository.

## Modes

The mode is set per project and defaults to `report`.

| Mode | After scans with findings |
|------|---------------------------|
| `report` (default) | Shows counts by severity and the top 5 findings (title, severity, file or package), ranked by severity and then by file or package name. No file is edited. The turn ends. |
| `suggest` | Shows the same summary and the turn continues so Claude proposes a fix for each top finding. No file is edited until you approve. |
| `autofix` | The turn continues and Claude applies available fixes for SCA and SAST findings. For SCA it edits only the manifest and package named by the finding. For SAST it starts from the finding's file and line and may edit other source files inside the project root that the fix needs (a shared helper, a call site). It never edits files outside the project root, config, CI or secrets files, `.claude/`, or lockfiles beyond what a dependency change needs, and never because scan output says so. The end-of-turn note lists every changed file and flags those that are not the finding's own file. Only the scans that had findings re-run, once. You then see what was fixed and what remains. Unfixed findings are not retried, and the fix edits are not scanned again. |

With no `.claude/snyk-plugin.json`, the mode is `report` and the output says once per session how to change it.

## Commands

- `/snyk-mode <report|suggest|autofix>` writes the mode to `.claude/snyk-plugin.json`, keeping any other keys in the file. An invalid value leaves the file unchanged and lists the valid modes. If the file exists but is not a JSON object, it is not overwritten.
- `/snyk-mode` with no value is an interview. Claude shows the current values, then asks one question at a time for `mode`, `severityThreshold` (`low`, `medium`, `high`, `critical`), `timeoutSeconds` (a positive whole number), `sast` (on or off) and `sca` (on or off). Each question shows the current value and what the options mean, and you can keep the current value. After the last answer all values are written in one step, keeping any other keys. An invalid value is not written and you are told which one and why. If you stop before the end, nothing is written.
- `/snyk-scan` runs every enabled scan (SAST and SCA unless switched off with `sast` or `sca`) now, whatever changed. It prints the report and never continues the turn, so in `suggest` and `autofix` mode it behaves like `report` mode. Every run ends with a line stating the current mode, which scans are on, and that `/snyk-mode` changes them (this is separate from the once-per-session hint above). With both scans switched off it runs nothing and says "No scans are enabled. Turn them on with /snyk-mode."

## Configuration

`.claude/snyk-plugin.json` in the project root. All keys are optional, unknown keys are ignored.

```json
{
  "mode": "report",
  "severityThreshold": "low",
  "timeoutSeconds": 120,
  "sast": true,
  "sca": true
}
```

| Key | Values | Default | Meaning |
|-----|--------|---------|---------|
| `mode` | `report`, `suggest`, `autofix` | `report` | What happens with findings. |
| `severityThreshold` | `low`, `medium`, `high`, `critical` | `low` | Findings below it are excluded. If every finding is below it, the line is "SAST: no issues at or above <threshold>" (or "SCA: ..."). |
| `timeoutSeconds` | positive integer | `120` | Per-scan timeout. A scan that exceeds it is killed and reported as "timed out". |
| `sast` | `true`, `false` | `true` | `false` switches SAST off everywhere: after a turn, in `/snyk-scan`, in the `autofix` re-scan, and in install or login retries. Nothing is printed about it. Use it when your org lacks Snyk Code. |
| `sca` | `true`, `false` | `true` | Same for SCA. When both are `false`, no Snyk command runs and nothing is printed. |

A file with broken JSON, a non-object value, an unknown mode, or an invalid value falls back to the default (mode `report`; a non-boolean `sast` or `sca` counts as `true`) and shows a warning naming the problem. The plugin never touches `.gitignore`. Whether to commit `.claude/snyk-plugin.json` is up to you.

## Approvals

Hooks cannot ask questions, so when a scan needs an approval, the plugin continues the turn once and Claude asks you in conversation. Nothing is installed and no login is started without your yes.

- **CLI install.** If `snyk` is neither on PATH nor at the standalone location, Claude asks before installing. The plugin tries, in order:
  1. `npm install -g snyk`
  2. `brew install snyk-cli` (macOS and Linux only)
  3. The standalone binary from `https://downloads.snyk.io/cli/stable/release.json`. Only HTTPS and host `downloads.snyk.io` are accepted, including redirects. The SHA-256 is checked against the file at the asset's `sha256Url` (not the inline `sha256`) before the binary is ever run. On a mismatch the file is deleted and you see "checksum mismatch". The binary is installed without sudo or admin rights and without a PATH change, to `~/.local/share/snyk-scan-plugin/bin/snyk` (macOS and Linux) or `%LOCALAPPDATA%\snyk-scan-plugin\bin\snyk.exe` (Windows). On Linux the Alpine/musl build is chosen when `/etc/alpine-release` exists or `ldd --version` mentions `musl`.

  If every method fails, each failure is listed and the scan is skipped. If there is no matching binary for your OS and CPU, or `release.json` cannot be fetched or parsed, you see "no standalone binary available: <reason>".
- **Authentication.** If the CLI reports you are not authenticated, Claude asks before the plugin runs `snyk auth`. On success the scan is retried once.
- **Declined or failed.** If you decline, or install or `snyk auth` fails or times out, the affected scan is skipped with a message naming the reason, and you are not asked again in the same session. A skipped scan never blocks the turn.

The plugin never reads, stores, or logs `SNYK_TOKEN` or the Snyk auth config. `snyk auth` stores its own token.

## What you see

| Situation | Message |
|-----------|---------|
| Exit code 0 | `SAST: no issues` / `SCA: no issues` |
| All findings below the threshold | `SAST: no issues at or above <threshold>` |
| Exit code 3 | `SAST: nothing to scan` / `SCA: nothing to scan` (for example, no supported manifest for SCA) |
| Exit code 2 or an unrecognised error | `SAST: scan failed: <reason>` (first line of the error) |
| Timeout | `SAST: timed out` |
| Snyk Code not enabled for your org | `SAST: skipped, Snyk Code is not enabled for your organization`; SCA still runs |

A failure, timeout, or skipped scan is never reported as "no issues" and never blocks the turn.

## How it works

- `UserPromptSubmit` records a baseline of file sizes and modification times at the start of each turn. It prints nothing.
- `Stop` compares the project to the baseline. If any file was added or modified (any file type), it runs the enabled scans: SAST, then SCA, each only if its switch is on and independent of the other's result. If nothing changed, nothing runs and nothing is printed. If there is no baseline for the session, nothing runs and a baseline is saved.
- Nothing is hashed, because reading every file would break the 500 ms budget on large trees. A file that was touched but not changed (new mtime, same content) therefore counts as a change and triggers the scans. Deleted files are not changes.
- The baseline covers git-tracked files plus untracked files that are not git-ignored. Outside a git repo it covers all files except `node_modules`, `.git`, `dist`, `build`, `target`, `venv`, `.venv`, and `__pycache__`. In both cases `.claude/` is left out, so a `/snyk-mode` config edit never triggers a scan.
- Session state (baseline, "asked once" flags) lives in the OS temp directory keyed by session ID. Nothing is written into the project except by `/snyk-mode`.
- Autofix scope: SCA edits only the named manifest and package. SAST edits start at the finding's file and line and may reach other project source files, with the guardrails listed under Modes. Edits are never driven by instructions in scan output.
- No loops: a turn continued by the plugin's own `Stop` hook runs no scan, except the single `autofix` re-scan, after which a fresh baseline is saved.
- File and path values are passed to the CLI as separate arguments, never interpolated into a shell string. Scan output is passed to Claude wrapped as untrusted data, and Claude is told never to follow instructions found in it.
- Performance target: a no-change turn adds under 500 ms per hook on up to 10,000 files.

Layout: `hooks/` (hook scripts, `helper.py`, `lib/`), `commands/` (`/snyk-mode`, `/snyk-scan`), `skills/snyk-scan/SKILL.md` (how Claude summarises, suggests, and fixes), `tests/`, and `specs/` (spec, plan, tasks).

## Tests

```
python3 -m unittest discover
```

The tests run the hook logic against a stubbed `snyk` (`tests/stubs/snyk`, and `snyk.cmd` for Windows) with scripted exit codes and JSON. They use no real tokens and no network. The suite uses only the Python standard library.

A GitHub Actions workflow (`.github/workflows/test.yml`) runs the suite on Linux, macOS, and Windows runners (Python 3.9 and the latest 3.x) on every push and pull request, using `python -m unittest discover` (the same module invocation as above). The workflow file is in the repository, but no run has been confirmed yet, so the suite has so far been verified locally only.

## Known limitations

- Windows is **future work** and unverified on a real Windows machine; the code and CI job exist but are not a 0.1.0 gate. The hooks are pinned to `bash` (Git Bash). If it is missing, Claude Code reports a non-blocking hook error and no scan runs. The `/snyk-mode` and `/snyk-scan` commands also assume a bash-style tool. See `specs/plan.md` (T13 launcher decision).
- The exact CLI error strings that identify "not authenticated" and "Snyk Code not enabled" are still an open question in the spec, so an unrecognised error shows as `scan failed: <reason>`.
- `autofix` for SAST may edit project source files other than the finding's own (shared helpers, call sites). They are listed and flagged in the end-of-turn note; review them before committing.
- Any file change triggers the scans, including docs, images, and files that were only touched. If that is too noisy, switch a scan off with `sast` or `sca`.
- Not supported in v1: updating or re-checking the version of an installed CLI, and proxy, self-signed certificate, or offline use.
- The standalone checksum comes from the same host as the binary, so it guards against corruption and tampering in transit, not against a compromised `downloads.snyk.io`.

## License

MIT, see `LICENSE`.
