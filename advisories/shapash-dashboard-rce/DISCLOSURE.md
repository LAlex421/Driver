# Disclosure & bounty plan — shapash dashboard RCE

This is a live, unreported 0-day. Handle via coordinated disclosure. Do **not** post the
exploit publicly (issue/PR/social) before a fix is agreed.

## Where to submit (pick one or both)

1. **huntr (AI/ML OSS bug bounty)** — https://huntr.com
   - shapash is open-source AI/ML tooling, which is huntr's scope. huntr runs coordinated
     disclosure *for you* (they notify/work with maintainers) and pays a bounty if accepted.
   - Submit as a new vulnerability report against the shapash package/repo. Paste the
     summary below, attach/inline `poc.py`, and give the CVSS and fix.
   - Confirm shapash is in-scope on the live site first (program list changes; I could not
     load huntr.com from the research environment).

2. **MAIF/shapash GitHub Security Advisory (private)** — https://github.com/MAIF/shapash
   - Repo → **Security** → **Report a vulnerability** (private advisory). If disabled, email
     the maintainers rather than filing a public issue.
   - GitHub can mint the CVE through the advisory once maintainers confirm.

> If you want both the bounty and smooth maintainer coordination, huntr is the primary route;
> it handles maintainer contact and CVE. Don't double-disclose publicly in the meantime.

## Ready-to-paste report

**Title:** Unauthenticated RCE in Shapash web dashboard via `eval()` on Dash callback id (`smart_app.py:2997`)

**Affected:** shapash 2.2.0 – 2.9.0 (latest); no fixed release. Sink introduced in 2.2.0 with the filter-dropdown feature; absent in ≤2.1.1. Runs on `dash>=2.3.1,<3.0.0`.

**Type:** Code Injection / Remote Code Execution (CWE-94/95). Unauthenticated.

**Summary:** `shapash/webapp/smart_app.py` (`layout_filter`) computes
`button_id = ctx.triggered[0]["prop_id"].split(".")[0]` and then runs
`eval(button_id)["index"]`. In Dash, the triggered `prop_id` is taken from the
client-supplied `changedPropIds` in the POST to `/_dash-update-component`, so an attacker who
can reach a running shapash dashboard controls the argument to `eval()` and achieves arbitrary
code execution on the host. No authentication is required.

**PoC:** (attached `poc.py` — non-destructive; creates only a local marker). Sends one crafted
callback request with
`changedPropIds = ["getattr(__import__('os'),'system')('<cmd>').n_clicks"]`. The
`.split(".")[0]` keeps the dot-free `getattr(__import__('os'),'system')('<cmd>')` intact, and
`eval()` executes it. Verified on dash 2.18.2 / CPython 3.13 — the command runs (marker file
created).

**Impact / CVSS:** Arbitrary command execution on the dashboard host. Suggested CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 (Critical) for a network-exposed dashboard; High if
strictly loopback-bound (still reachable via DNS-rebinding/CSRF since the endpoint is
unauthenticated and state-changing).

**Fix:** Replace `eval(button_id)` with `json.loads(button_id)`:
```python
import json
filter_id_to_remove = json.loads(button_id)["index"]
```
Dash serialises pattern-matching ids as JSON, so this is behaviour-preserving (parses
`{"index":0,"type":"del_dropdown_button"}` correctly) and refuses code payloads
(`JSONDecodeError`). Alternatively use Dash's `ctx.triggered_id`.

**Discoverer:** <your name / handle>.
