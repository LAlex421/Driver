# Private disclosure report — ready to submit

**How to submit (coordinated disclosure):**
Go to https://github.com/ktbyers/netmiko → **Security** tab → **Report a vulnerability**
(GitHub Private Vulnerability Reporting). Paste the report below. If that form is disabled,
email the maintainer (Kirk Byers) rather than opening a public issue. Do **not** open a public
issue or PR describing the exploit until the maintainer has responded and agreed a disclosure
date.

---

**Title:** Exponential ReDoS in Nokia SR-OS / ISAM `set_base_prompt` prompt regex

**Affected:** netmiko 4.8.0 (current); pattern present in earlier 4.x as well
`netmiko/nokia/nokia_sros.py` (`NokiaSrosSSH.set_base_prompt`, ~line 67)
`netmiko/nokia/nokia_isam.py` (`NokiaIsamSSH.set_base_prompt`, ~line 25)

**Summary:**
Both classes parse the device prompt with
`re.search(r"\*?(.*?)(>.*)*#", cur_base_prompt)`. The sub-expression `(>.*)*` is a nested
quantifier whose inner `.*` also matches `>`, so on a prompt containing a run of `>`
characters and no terminating `#`, Python's `re` engine backtracks exponentially.
`cur_base_prompt` is the device's prompt returned by `find_prompt()` with no length limit or
sanitisation, so a malicious/compromised device (or a MITM on the management channel) can
return a ~30–40 byte prompt that pins the host CPU at 100% effectively forever — a denial of
service on the automation host.

**Proof of concept (no device required — this is the exact library regex):**
```python
import re, time
EVIL = re.compile(r"\*?(.*?)(>.*)*#")   # netmiko nokia_sros.py / nokia_isam.py
for n in range(16, 28, 2):
    s = ">" * n                          # a prompt a hostile device could emit
    t0 = time.perf_counter(); EVIL.search(s); print(n, round(time.perf_counter()-t0, 3), "s")
```
Observed (CPython 3.13): n=20 → 0.21s, n=22 → 0.85s, n=24 → 3.3s, n=26 → >10s (aborted).
Each +2 characters ≈ ×4 time (O(2^(n/2))). A ~40-char prompt will not complete.

**Impact:** Availability (CWE-1333 / CWE-400). No code execution or data exposure.
Suggested severity Medium, CVSS 3.1 `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` (6.5); High (7.5,
UI:N) for unattended collectors that poll devices on a schedule.

**Suggested fix (behaviour-preserving, backtracking-free):**
The intent is only to drop a leading `*` and keep the hostname before any `>`/`#`:
```python
match = re.search(r"\*?([^>#]*)", cur_base_prompt)
if match:
    self.base_prompt = match.group(1)
```
Verified: for a normal prompt `*A:hostname>config#`, both the original and the proposed
pattern capture `A:hostname` in group(1); the replacement is linear (100,000 `>` → <1ms).
Alternatives: an atomic group / possessive quantifier on 3.11+ (`r"\*?(.*?)(?:>.*)*+#"`), or
capping the prompt length before matching.

**Discoverer:** <your name / handle here> — found by source audit of netmiko 4.8.0.
Happy to submit the fix as a PR once you've acknowledged, and to coordinate a disclosure
date and CVE.
