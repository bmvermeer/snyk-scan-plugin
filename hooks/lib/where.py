"""Find an executable on PATH without ever picking one from the current directory.

shutil.which on Windows searches the current directory first, and CreateProcess does
too for a bare name. The hooks run with the project as the working directory, so a
repository could plant `snyk.exe` or `git.exe`. This lookup only uses absolute PATH
entries. On other systems it behaves like `which`.
"""
import os
import shutil


def which(name, path=None, windows=None, pathext=None):
    windows = (os.name == "nt") if windows is None else windows
    path = os.environ.get("PATH", os.defpath) if path is None else path
    if not windows:
        return shutil.which(name, path=path)
    pathext = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD") if pathext is None else pathext
    exts = [e for e in pathext.split(";") if e]
    names = [name] if os.path.splitext(name)[1].lower() in [e.lower() for e in exts] else []
    for ext in exts:
        names.extend([name + ext, name + ext.lower()])
    for directory in path.split(os.pathsep):
        directory = directory.strip().strip('"')
        if not directory or not os.path.isabs(directory):
            continue
        for candidate in names:
            full = os.path.join(directory, candidate)
            if os.path.isfile(full):
                return full
    return None
