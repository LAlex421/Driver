# Private disclosure report — ready to submit

**How to submit (coordinated disclosure):**
https://github.com/ktbyers/netmiko → **Security** tab → **Report a vulnerability**
(GitHub Private Vulnerability Reporting). Paste the report below. If the form is disabled,
email the maintainer (Kirk Byers). Do **not** open a public issue/PR describing the exploit
until the maintainer has responded and agreed a disclosure date.

---

**Title:** ReDoS cluster in device-prompt parsing across several `set_base_prompt` overrides

**Affected:** netmiko 4.8.0 (current); same idiom in earlier 4.x.

| File / line | Class | Regex (via `re.search` on the device prompt) | Growth |
|-------------|-------|-----------------------------------------------|--------|
| `netmiko/nokia/nokia_sros.py:67` | `NokiaSrosSSH` | `\*?(.*?)(>.*)*#` | Exponential |
| `netmiko/nokia/nokia_isam.py:25` | `NokiaIsamSSH` | `\*?(.*?)(>.*)*#` | Exponential |
| `netmiko/extreme/extreme_exos.py:41` | `ExtremeExosBase` | `[\*\s]*(.*)\.\d+` | Polynomial (~cubic) |
| `netmiko/cisco/cisco_asa_ssh.py:116` | `CiscoAsaSSH` | `(.*)\(conf.*` | Polynomial (~quadratic) |

**Summary:**
Each of these `set_base_prompt()` overrides runs a regex over `cur_base_prompt`, which is
the prompt returned by `BaseConnection.find_prompt()` — i.e. bytes the remote device sent,
with no length limit or sanitisation. The patterns backtrack super-linearly, so a
malicious/compromised managed device (or a MITM on the management channel) can return a
crafted prompt that pins the automation host's CPU — a DoS. The Nokia pattern is
exponential: ~30 bytes is enough to hang effectively forever. The hang is in pure-Python
`re`, so network timeouts don't interrupt it.

**Proof of concept (no device needed — exact library regexes):**
```python
import re, time
cases = {
    "nokia":   (re.compile(r"\*?(.*?)(>.*)*#"),  lambda n: ">"*n,          range(16,28,2)),
    "extreme": (re.compile(r"[\*\s]*(.*)\.\d+"), lambda n: " "*n+"!",      (500,1000,2000)),
    "asa":     (re.compile(r"(.*)\(conf.*"),     lambda n: "a "*n+"!",     (5000,10000,20000)),
}
for name,(rx,atk,ns) in cases.items():
    for n in ns:
        s=atk(n); t0=time.perf_counter(); rx.search(s); print(name, n, round(time.perf_counter()-t0,3),"s")
```
Observed (CPython 3.13): nokia n=24 → 3.5s, n=26 → >10s; extreme n=1000 → 1.5s, n=2000 → >10s;
asa n=20000 → 7.6s. Nokia grows ×4 per +2 chars (`O(2^(n/2))`).

**Impact:** Availability (CWE-1333 / CWE-400). No code execution or data exposure.
Nokia: suggested Medium, CVSS 3.1 `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` (6.5); High (7.5,
UI:N) for unattended collectors. Extreme/ASA: Low–Medium (polynomial; larger prompt needed).

**Suggested fixes (all verified to capture the identical `group(1)` on normal prompts and to
be linear to 100k+ chars):**
```python
# nokia_sros.py:67 and nokia_isam.py:25
match = re.search(r"\*?([^>#]*)", cur_base_prompt)
# extreme_exos.py:41
match = re.search(r"^\*?\s*(\S.*?)\.\d+", cur_base_prompt)
# cisco_asa_ssh.py:116
match = re.search(r"^(.*?)\(conf", cur_base_prompt)
```
Root-cause guidance for the class: anchor with `^` so `re.search` doesn't re-scan from every
offset; don't wrap a quantified group in another quantifier (`(>.*)*`); don't place two
quantifiers over overlapping classes back-to-back (`[\*\s]*(.*)`); optionally cap prompt
length before matching. (Cf. upstream issue #3208 — a similar prompt-regex fix.)

**Discoverer:** <your name / handle here> — found by source audit of netmiko 4.8.0.
Happy to submit the fixes as a single PR once you've acknowledged, and to coordinate a
disclosure date and CVE.
