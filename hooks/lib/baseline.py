"""File baseline and diff (REQ-3, 4, 7, 8, 10).

A baseline maps relative path (always "/" separators) to [size, mtime_ns].
Every file in the file set is recorded, whatever its type (REQ-1, 2), except anything
under `.claude/` (REQ-7), so `/snyk-mode` config edits never count as a change. A file counts as
changed when it is new or its size or mtime differs. Nothing is hashed:
reading every file of a 10,000-file tree exceeds the REQ-4 budget (plan R4), so a no-change
turn stays at one directory listing plus stats.
"""
import os
import stat
import subprocess

from . import where

FALLBACK_EXCLUDES = frozenset(
    [".claude", "node_modules", ".git", "dist", "build", "target", "venv", ".venv", "__pycache__"]
)


def _git_files(root):
    git = where.which("git")
    if not git:
        return None
    try:
        r = subprocess.run(
            [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    paths = r.stdout.decode("utf-8", "surrogateescape").split("\0")
    return [p for p in paths if p and p != ".claude" and not p.startswith(".claude/")]


def _walk_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in FALLBACK_EXCLUDES]
        rel_dir = os.path.relpath(dirpath, root)
        for name in filenames:
            out.append(name if rel_dir == "." else rel_dir.replace(os.sep, "/") + "/" + name)
    return out


def list_files(root):
    found = _git_files(root)
    return found if found is not None else _walk_files(root)


def take(root, previous=None):  # `previous` is accepted for callers that re-baseline
    """Build a baseline: relative path -> [size, mtime_ns] for every regular file."""
    result = {}
    for rel in list_files(root):
        full = os.path.join(root, *rel.split("/"))
        try:
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                continue
        except OSError:
            continue
        result[rel] = [st.st_size, st.st_mtime_ns]
    return result


def changes_since(root, base):
    """Sorted paths added or modified since `base`; empty means no change.

    Returns None when there is no baseline (REQ-8). Deleted files are not changes.
    """
    if base is None:
        return None
    changed = []
    for rel, entry in take(root).items():
        old = base.get(rel)
        if old is None or old != entry:
            changed.append(rel)
    return sorted(changed)
