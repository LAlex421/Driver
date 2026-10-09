# huntr submission — Taipy GUI pandas-query injection + ReDoS

Paste into huntr's "Report a vulnerability" form. Confirm `taipy` / `taipy-gui` is in scope on
the live site; if not, use Taipy's (Avaiga) GitHub security advisory process.

## Form fields
- **Package / registry:** `taipy-gui` (pip / PyPI) — also bundled in `taipy`.
- **Repository:** https://github.com/Avaiga/taipy
- **Affected version:** 3.0.0 through 4.0.2 (latest); no fixed release. (Verified 3.0.0, 3.1.4,
  4.0.2.)
- **Vulnerable file:** `taipy/gui/data/pandas_data_accessor.py`, `_PandasDataAccessor.__get_data`
  (the `filters` loop building `df.query(...)`); entry point `taipy/gui/gui.py` `DATA_UPDATE`.
- **Weakness (CWE):** CWE-943 / CWE-74 (query-expression injection) + CWE-1333 (ReDoS).
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` ≈ 9.1 (High/Critical).

## Title
Unauthenticated pandas `DataFrame.query` expression injection and ReDoS in Taipy GUI table filtering

## Description
**Overview.** Taipy GUI's table component sends filter requests over its WebSocket. The server
(`_PandasDataAccessor.__get_data`) builds a pandas `df.query()` string from the client-supplied
`filters` payload. String values are bound via `@vars`, but the operator (`action`) and column
(`col`) are interpolated **raw**, and the `contains` action feeds the client value directly to
`.str.contains(<regex>)`. The query runs under the pandas **python** engine. A remote,
unauthenticated client thus controls the query expression.

**Reachability.** `gui.py`: a `DATA_UPDATE` WebSocket message →
`__request_data_update(name, payload)` → `get_data(var_name, value, payload)` → `__get_data`,
with `payload["filters"]` attacker-controlled. Taipy's socket.io also uses wildcard CORS with
credentials (CVE-2026-85183), so this is reachable cross-origin (drive-by).

**Steps to reproduce.** Connect to the Taipy app WebSocket (or from any origin, per the CORS
issue) and send a `DATA_UPDATE` message whose `payload.filters` is, e.g.:
- Filter bypass / injection: `[{"col":"salary","value":0,"action":"> -1 or \`salary\` > 0 #"}]`
  → the server runs `` `salary` > -1 or `salary` > 0 # 0`` and returns all rows.
- ReDoS: `[{"col":"user","value":"(a+)+$","action":"contains"}]` → `.str.contains("(a+)+$")`
  backtracks catastrophically and hangs the worker.

**PoC.** Attached `poc.py` replicates the exact upstream filter-builder and demonstrates (1)
filter bypass, (2) blind boolean data exfiltration, (3) ReDoS hang (>6s on a tiny frame).
Non-destructive.

**Impact.** Unauthenticated remote attacker can bypass server-side data filters, exfiltrate
dataframe contents via a boolean oracle, and cause denial of service via a crafted regex.
Untrusted input into `df.query(engine="python")` is the same class D-Tale received
**CVE-2024-8862** for (command execution); full RCE not demonstrated here and reported
conservatively.

## Suggested fix
Replace the query-string construction with boolean masks built from a **whitelisted** operator
set and a **validated** column name; for `contains`, use `regex=False` or escape + length-cap
the pattern. Do not interpolate `col`/`action` into a `df.query` string.

## Notes for the reviewer
- Independent discovery; prior art checked — no existing advisory for this data-accessor sink.
- Severity assumes the WebSocket is reachable (default) and the CORS amplifier (CVE-2026-85183);
  score the confidentiality/RCE elements to your policy.
- **Discoverer:** <your name / handle>.
