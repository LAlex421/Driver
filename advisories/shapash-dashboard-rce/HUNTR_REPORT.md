# huntr submission — Shapash dashboard RCE

Copy these into the huntr "Report a vulnerability" form (https://huntr.com). First confirm
`shapash` is in huntr's scope on the live site; if not listed, you can request it be added, or
use the MAIF/shapash GitHub private advisory route (see DISCLOSURE.md) for the CVE.

---

## Form fields

- **Package / registry:** `shapash` (pip / PyPI)
- **Repository:** https://github.com/MAIF/shapash
- **Affected version:** `>= 2.2.0, <= 2.9.0` (latest; no fixed release). Sink absent in ≤ 2.1.1.
- **Vulnerable file / line:** `shapash/webapp/smart_app.py` → `layout_filter` callback →
  `eval(button_id)` (line 2997 in 2.9.0; equivalent line in every release since 2.2.0).
- **Weakness (CWE):** CWE-95 (Eval Injection) / CWE-94 (Code Injection). RCE.
- **CVSS 3.1 vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **9.8 Critical**
  (justified by the default `host="0.0.0.0"` bind; note the exposure explicitly in the report).

## Title

Unauthenticated Remote Code Execution in Shapash web dashboard via `eval()` on a client-controlled Dash callback id

## Description

**Overview.** Shapash ships an interactive web dashboard started with
`SmartExplainer.run_app()` (or the bundled `webapp_launch.py`). The Dash callback
`layout_filter` in `shapash/webapp/smart_app.py` parses the id of the component that triggered
the callback with Python's `eval()`:

```python
button_id = ctx.triggered[0]["prop_id"].split(".")[0]
...
else:
    filter_id_to_remove = eval(button_id)["index"]   # smart_app.py:2997
```

In Dash, `callback_context.triggered[0]["prop_id"]` is populated from the **`changedPropIds`
field of the client's POST** to `/_dash-update-component`. That value is not authenticated and
is not validated to be a real component id, so an attacker who can reach the dashboard fully
controls the string passed to `eval()` → arbitrary Python execution on the server.

**Network-exposed by default.** `run_app()` sets `host = "0.0.0.0"` when `host` is not given
(docstring: *"Defaults to `0.0.0.0`, allowing external access."*), and the bundled launchers
bind `0.0.0.0:8080`. No authentication protects `/_dash-update-component`.

**Steps to reproduce.**
1. Start any Shapash dashboard (e.g. `xpl.run_app()`), which listens on `0.0.0.0`.
2. Send one unauthenticated POST to `/_dash-update-component` whose `changedPropIds` is a
   Python expression ending in `.n_clicks` (the suffix is stripped by `.split(".")[0]`). Use a
   dot-free expression so it survives the split, e.g.:
   `getattr(__import__('os'),'system')('id > /tmp/pwned').n_clicks`
3. `button_id` becomes `getattr(__import__('os'),'system')('id > /tmp/pwned')` and `eval()`
   executes it. (`eval(...)["index"]` then raises `TypeError`, but the command already ran.)

**Proof of concept.** The attached `poc.py` replicates the exact callback and drives it through
Dash's Flask test client with the crafted request; it is non-destructive (creates only a local
marker file). Verified on CPython 3.13 with `dash` 2.18.2 (shapash pins `dash>=2.3.1,<3.0.0`).
Output: `RESULT: VULNERABLE (code executed)`.

**Impact.** Unauthenticated remote code execution on the host running the dashboard: full
command execution, data theft, lateral movement, and compromise of any credentials/models on
that host.

## Suggested fix

Parse the Dash pattern-matching id with `json.loads` instead of `eval` (behaviour-preserving —
Dash serialises these ids as JSON; verified it returns the correct `{"index": ...}` dict and
rejects code payloads with `JSONDecodeError`):

```python
import json
filter_id_to_remove = json.loads(button_id)["index"]
```

Or, on Dash ≥ 2.4, use the parsed id directly via `ctx.triggered_id` and avoid manual parsing.

## Notes for the reviewer

- Discovered independently by source audit; prior art checked — no existing CVE/advisory for
  this sink as of 2026-10-09.
- Severity assumes the default `0.0.0.0` bind. A deployment that overrides `host` to loopback
  is still reachable via DNS-rebinding/CSRF (unauthenticated, state-changing POST), but score
  that case lower if you prefer.
