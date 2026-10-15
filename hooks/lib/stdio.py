"""Make stdin and stdout UTF-8. Windows pipes default to the ANSI code page, which
garbles non-ASCII paths in the hook JSON and fails on printing them."""
import sys


def use_utf8():
    for stream, errors in ((sys.stdin, "replace"), (sys.stdout, "replace"), (sys.stderr, "replace")):
        try:
            stream.reconfigure(encoding="utf-8", errors=errors)
        except (AttributeError, ValueError, OSError):
            pass
