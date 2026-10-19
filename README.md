# snyk-scan-plugin

A Claude Code / Cowork plugin that runs Snyk scans automatically after each Claude turn.

- **SAST** (`snyk code test`) runs if the turn changed source files.
- **SCA** (`snyk test --all-projects`) runs if the turn changed dependency manifests or lockfiles.
- Each scan runs at most once per turn, on the project root only. A turn that changed nothing relevant runs no scan and prints nothing.

Version `0.1.0`, MIT license. Status: not yet released. The manual end-to-end run on macOS and Linux (task T17) is still pending. Windows support is future work and has not been verified on a real Windows machine (see [Known limitations](#known-limitations)).

Out of scope: IaC, container, and secrets scanning, `snyk monitor`, a custom MCP server, and anything that reads or stores Snyk tokens.

## Requirements

- **Python 3.9 or newer.** The hooks are Python 3, standard library only. The hook launcher tries `python3`, then `python`, then `py -3`, and uses the first one that is 3.9 or newer. If none is found, a one-line message says Python 3.9+ is required, scans are off, and the turn is not blocked.
- The **Snyk CLI**, or approval to install it (see [Approvals](#approvals)).
- A Snyk account for `snyk auth`.
- Git is optional (it only changes how files are listed, see [How it works](#how-it-works)).
- The hooks run through `bash` (`"shell": "bash"` in `hooks/hooks.json`). On Windows that means Git Bash must be available.

## Install

The project is meant to be installed through two channels: the Claude Code plugin marketplace and directly from GitHub. The repository is <https://github.com/bmvermeer/snyk-scan-plugin>. There is no published marketplace entry yet.

- **Marketplace:** add the marketplace that lists `snyk-scan-plugin`, then install the plugin with Claude Code's `/plugin` commands. (Marketplace name: to be decided.)
- **GitHub:** add the `snyk-scan-plugin` repository as a plugin source with Claude Code's `/plugin` commands. Repository: `bmvermeer/snyk-scan-plugin` (`https://github.com/bmvermeer/snyk-scan-plugin`).
- **Local checkout (development):** `claude --plugin-dir /path/to/snyk-scan-plugin` loads the plugin from a clone of this repository.

## Modes

The mode is set per project and defaults to `report`.

| Mode | After scans with findings |
|------|---------------------------|
| `report` (default) | Shows counts by severity and the top 5 findings (title, severity, file or package), ranked by severity and then by file or package name. No file is edited. The turn ends. |
| `suggest` | Shows the same summary and the turn continues so Claude proposes a fix for each top finding. No file is edited until you approve. |
| `autofix` | The turn continues and Claude applies available fixes for SCA and SAST findings. It edits only the file and line (SAST) or the manifest and package (SCA) named by a finding's structured fields. Only the scans that had findings re-run, once. You then see what was fixed and what remains. Unfixed findings are not retried, and the fix edits are not scanned again. |

With no `.claude/snyk-plugin.json`, the mode is `report` and the output says once per session how to change it.

## Commands

- `/snyk-mode <report|suggest|autofix>` writes the mode to `.claude/snyk-plugin.json`, keeping any other keys in the file. An invalid value leaves the file unchanged and lists the valid modes. If the file exists but is not a JSON object, it is not overwritten.
- `/snyk-mode` with no value is an interview. Claude shows the current values, then asks one question at a time for `mode`, `severityThreshold` (`low`, `medium`, `high`, `critical`) and `timeoutSeconds` (a positive whole number). Each question shows the current value and what the options mean, and you can keep the current value. After the last answer all values are written in one step, keeping any other keys. An invalid value is not written and you are told which one and why. If you stop before the end, nothing is written.
- `/snyk-scan` runs both SAST and SCA now, whatever changed. It prints the report and never continues the turn, so in `suggest` and `autofix` mode it behaves like `report` mode. Every run ends with a line stating the current mode and that `/snyk-mode` changes it (this is separate from the once-per-session hint above).

## Configuration

`.claude/snyk-plugin.json` in the project root. All keys are optional, unknown keys are ignored.

```json
{
  "mode": "report",
  "severityThreshold": "low",
  "timeoutSeconds": 120
}
```

| Key | Values | Default | Meaning |
|-----|--------|---------|---------|
| `mode` | `report`, `suggest`, `autofix` | `report` | What happens with findings. |
| `severityThreshold` | `low`, `medium`, `high`, `critical` | `low` | Findings below it are excluded. If every finding is below it, the line is "SAST: no issues at or above <threshold>" (or "SCA: ..."). |
| `timeoutSeconds` | positive integer | `120` | Per-scan timeout. A scan that exceeds it is killed and reported as "timed out". |

A file with broken JSON, a non-object value, an unknown mode, or an invalid value falls back to the default (mode `report`) and shows a warning naming the problem. The plugin never touches `.gitignore`. Whether to commit `.claude/snyk-plugin.json` is up to you.

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
| Exit code 3 | nothing to scan (for example, no supported manifest for SCA) |
| Exit code 2 or an unrecognised error | `scan failed: <reason>` (first line of the error) |
| Timeout | `timed out` |
| Snyk Code not enabled for your org | SAST is skipped with an explanation, SCA still runs if due |

A failure, timeout, or skipped scan is never reported as "no issues" and never blocks the turn.

## How it works

- `UserPromptSubmit` records a baseline of file hashes at the start of each turn. It prints nothing.
- `Stop` compares the project to the baseline. A source change runs SAST, a dependency change runs SCA, and a dependency-only or source-only turn runs only the matching scan. If there is no baseline for the session, nothing runs and a baseline is saved.
- The baseline covers git-tracked files plus untracked files that are not git-ignored. Outside a git repo it covers all files except `node_modules`, `.git`, `dist`, `build`, `target`, `venv`, `.venv`, and `__pycache__`.
- Source files are matched by extension, case-insensitively: `.js .jsx .mjs .cjs .ts .tsx .mts .cts .vue .py .java .kt .kts .scala .groovy .go .rb .php .cs .vb .c .h .cc .cpp .cxx .hpp .m .mm .swift .dart .rs .ex .exs .cls .trigger`. `.html` is deliberately excluded.
- Dependency files are matched by exact file name: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `go.mod`, `go.sum`, `Gemfile`, `Gemfile.lock`, `packages.lock.json`, `composer.json`, `composer.lock`, plus any `*.csproj`.
- Session state (baseline, "asked once" flags) lives in the OS temp directory keyed by session ID. Nothing is written into the project except by `/snyk-mode`.
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
- Not supported in v1: updating or re-checking the version of an installed CLI, and proxy, self-signed certificate, or offline use.
- The standalone checksum comes from the same host as the binary, so it guards against corruption and tampering in transit, not against a compromised `downloads.snyk.io`.

## License

MIT, see `LICENSE`.
