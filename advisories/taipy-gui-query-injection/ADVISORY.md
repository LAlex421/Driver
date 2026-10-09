# Unauthenticated pandas-query injection + ReDoS in Taipy GUI table filtering

> **Status: DRAFT — NOT YET DISCLOSED.** Appears **novel** (no advisory for Taipy's
> data-accessor query injection as of 2026-10-09). Coordinated disclosure: report privately
> via huntr / the Taipy (Avaiga) security process before any public mention. Keep the repo
> private until a fix ships.

## Summary

Taipy is a popular Python framework for building data/ML web apps. Its GUI table component
lets the browser request filtered/paginated data over a WebSocket. The server builds a pandas
`DataFrame.query()` expression from the client-supplied `filters` payload and interpolates the
**column name** and the **operator (`action`)** into the query string *without sanitisation*,
then evaluates it with the pandas **python engine**. An unauthenticated client therefore
controls the pandas query expression, yielding server-side **filter bypass**, **blind data
exfiltration**, and **ReDoS denial of service** (and — per the D-Tale precedent,
CVE-2024-8862 — the recognised code-execution class for untrusted input reaching
`df.query(engine="python")`).

- **Package:** `taipy-gui` (PyPI; also shipped inside `taipy`)
- **Affected versions:** confirmed **3.0.0, 3.1.4, 4.0.2 (latest)** — i.e. the current 3.x–4.x
  line; no fixed release. (Same `__get_data` filter builder across all.)
- **Component:** `taipy/gui/data/pandas_data_accessor.py`, `_PandasDataAccessor.__get_data`
  (`right = f".str.contains({val})" ... else f" {action} {val}"`; `query += f"\`{col}\`{right}"`;
  `df = df.query(query)`), reached from `taipy/gui/gui.py` on a `DATA_UPDATE` WebSocket message.
- **Class:** Improper neutralisation in a data-query expression (CWE-943 / CWE-74); ReDoS
  (CWE-1333).
- **Auth:** none (GUI WebSocket; and reachable cross-origin — see "Amplifier").

## Vulnerable code

```python
# taipy/gui/data/pandas_data_accessor.py  (__get_data)
filters = payload.get("filters")                     # <- client-controlled (WebSocket)
...
for fd in filters:
    col = fd.get("col"); val = fd.get("value"); action = fd.get("action")
    if isinstance(val, str):
        vars.append(val)
    val = f"@vars[{len(vars)-1}]" if isinstance(val, str) else val   # values are bound (safe)
    right = f".str.contains({val})" if action == "contains" else f" {action} {val}"  # action RAW
    query += f"`{col}`{right}"                                         # col RAW
df = df.query(query)                                                  # python engine
```

`val` (string) is safely parameterised via `@vars[...]`, but **`action` and `col` are
interpolated verbatim** into the expression, and for `action == "contains"` the client value
becomes the **regex** in `.str.contains(...)`.

## Reachability (unauthenticated, client-driven)

`taipy/gui/gui.py` handles a WebSocket message:
```python
elif msg_type == _WsType.DATA_UPDATE.value:
    self.__request_data_update(str(message.get("name")), message.get("payload"))
```
→ `__request_data_update` → `_get_accessor().get_data(var_name, newvalue, payload)` →
`_PandasDataAccessor.__get_data(...)`. The `payload` (and thus `filters`) is attacker-supplied.

**Amplifier — cross-origin:** Taipy's socket.io server is configured with wildcard CORS and
credentials (**CVE-2026-85183**), so *any* web page a victim visits can open a credentialed
WebSocket to a victim's Taipy app and send the malicious `DATA_UPDATE` — making this
exploitable drive-by, not just by someone who can reach the port.

## Impact (demonstrated — see `poc.py`)

1. **Server-side filter bypass.** Injecting into `action` (e.g. `"> -1 or \`salary\` > 0 #"`;
   `#` comments out the trailing operand) lets the attacker replace the intended filter with an
   arbitrary boolean expression → returns rows/data the UI would not.
2. **Blind data exfiltration (boolean oracle).** Crafting conditions over any column reveals
   data a filter was meant to hide (e.g. "does an admin row satisfy X?") from the result count.
3. **ReDoS DoS.** The `contains` action passes the client string to `.str.contains(<regex>)`
   (regex enabled); a catastrophic pattern such as `(a+)+$` hangs the worker (verified > 6 s on
   a tiny frame → trivially scaled to a permanent hang).
4. **Code-execution class.** Untrusted input into `df.query(engine="python")` is the same sink
   D-Tale was assigned **CVE-2024-8862** for (command execution). Full RCE was **not**
   demonstrated here (pandas' expression grammar blocks lambdas/imports in this version), so it
   is reported as injection + DoS with RCE potential per precedent — don't overstate it.

## Suggested severity

High. Suggested CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` ≈ **9.1** (unauthenticated,
remote, confidentiality via filter bypass/exfiltration + availability via ReDoS). If the triage
team accepts the `df.query` code-execution class, it trends Critical; if they treat the
exfiltration as low-confidence, it settles around High (~7.5). Scope it honestly in the report.

## Remediation

Do not build a `df.query` string from client input. Options:
- Whitelist `action` to a fixed operator set (`==,!=,<,<=,>,>=,contains`) and map to **boolean
  masks**, not a query string: e.g. `mask = df[col] > value`, combined with `&`/`|`.
- Validate `col` against the actual dataframe columns (membership check), never interpolate it.
- For `contains`, call `series.str.contains(pat, regex=False)` or escape the pattern, and/or
  cap pattern length — never pass a raw client string as a regex.
- If a query string must be used, restrict to `engine="python"`-free boolean masking and reject
  any operator/column not on the allow-list.

## Credit

Independent discovery via a high-severity sink scan (`scripts/hisev_scan.py` + targeted grep)
and verification against Taipy's exact filter-builder. Prior art checked — no existing advisory
for this sink.
