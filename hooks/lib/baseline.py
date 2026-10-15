"""File baseline and diff (REQ-3, 4, 7, 8, 10).

A baseline maps relative path (always "/" separators) to [size, mtime_ns, sha256].
Only source and dependency files are recorded. Size and mtime let an unchanged file
skip hashing, which keeps a no-change turn to one directory listing plus stats.
"""
import hashlib
import os
import stat
import subprocess

from . import files, where

FALLBACK_EXCLUDES = frozenset(
    ["node_modules", ".git", "dist", "build", "target", "venv", ".venv", "__pycache__"]
)


class Changes(object):
    """Added or modified files since the baseline. Deleted files are not changes."""

    def __init__(self, source, dependency):
        self.source = source
        self.dependency = dependency

    def __bool__(self):
        return bool(self.source or self.dependency)


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
    return [p for p in r.stdout.decode("utf-8", "surrogateescape").split("\0") if p]


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


def _hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def take(root, previous=None):
    """Build a baseline. Entries equal in size and mtime to `previous` reuse its hash."""
    previous = previous or {}
    result = {}
    for rel in list_files(root):
        if files.classify(rel) is None:
            continue
        full = os.path.join(root, *rel.split("/"))
        try:
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                continue
            old = previous.get(rel)
            if old and old[0] == st.st_size and old[1] == st.st_mtime_ns:
                digest = old[2]
            else:
                digest = _hash(full)
        except OSError:
            continue
        result[rel] = [st.st_size, st.st_mtime_ns, digest]
    return result


def changes_since(root, base):
    """Return Changes against `base`, or None when there is no baseline (REQ-8)."""
    if base is None:
        return None
    source, dependency = [], []
    for rel, entry in take(root, base).items():
        old = base.get(rel)
        if old is not None and old[2] == entry[2]:
            continue
        (source if files.classify(rel) == files.SOURCE else dependency).append(rel)
    return Changes(sorted(source), sorted(dependency))
