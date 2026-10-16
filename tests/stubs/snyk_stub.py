"""Windows-side body of the snyk stub (snyk.cmd delegates here, so cmd.exe never echoes scripted text).

Mirrors tests/stubs/snyk (sh form): same SNYK_STUB_* environment contract.
"""
import os
import sys


def emit(stream, text):
    stream.buffer.write(text.encode("utf-8") + b"\n")
    stream.buffer.flush()


def main():
    env = os.environ.get
    log = env("SNYK_STUB_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(" ".join(sys.argv[1:]) + "\n")
    if sys.argv[1:2] == ["auth"]:
        if env("SNYK_STUB_AUTH_STDERR"):
            emit(sys.stderr, env("SNYK_STUB_AUTH_STDERR"))
        code = int(env("SNYK_STUB_AUTH_EXIT") or 0)
        authed = env("SNYK_STUB_AUTHED_FILE")
        if code == 0 and authed:
            try:
                open(authed, "a").close()
            except OSError:
                pass
        return code
    authed = env("SNYK_STUB_AUTHED_FILE")
    if authed and not os.path.exists(authed):
        emit(sys.stderr, "Authentication required (SNYK-0005)")
        return 2
    if env("SNYK_STUB_STDOUT"):
        emit(sys.stdout, env("SNYK_STUB_STDOUT"))
    if env("SNYK_STUB_STDERR"):
        emit(sys.stderr, env("SNYK_STUB_STDERR"))
    return int(env("SNYK_STUB_EXIT") or 0)


if __name__ == "__main__":
    sys.exit(main())
