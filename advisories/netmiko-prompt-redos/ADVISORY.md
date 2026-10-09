# ReDoS cluster in Netmiko device-prompt parsing (`set_base_prompt` overrides)

> **Status: DRAFT — NOT YET DISCLOSED.** Appears novel (no CVE / public advisory found as of
> 2026-10-09). Follow coordinated disclosure: report privately to the maintainers **before**
> publishing or requesting a CVE. See "Disclosure plan". Do not open a public issue/PR first.

## Summary

Several of Netmiko's per-vendor connection classes override `set_base_prompt()` and run a
regular expression over the device's prompt string to clean it up. Four of these regexes
exhibit super-linear (up to **exponential**) backtracking. Because the prompt is derived
from bytes the **remote device** sends (via `BaseConnection.find_prompt()`), with no length
cap or sanitisation before the match, a **malicious or compromised managed device** (or an
attacker performing MITM on the management channel) can return a short prompt that pins the
automation host's CPU — a denial of service on the management/automation plane.

This is a **class of bug**: the same unsafe idiom (unanchored, overlapping/nested greedy
quantifiers passed to `re.search` on device-controlled text) recurs across multiple drivers.

- **Package:** `netmiko` (PyPI) — the de-facto multi-vendor network-automation SSH library
- **Version analysed:** 4.8.0 (current)
- **Class:** Uncontrolled resource consumption / ReDoS (CWE-1333, CWE-400)
- **Trigger:** device-controlled prompt output
- **Impact:** CPU exhaustion / denial of service on the host running Netmiko

## Affected locations

| # | File / line | Class | Regex (via `re.search` on `cur_base_prompt`) | Complexity |
|---|-------------|-------|-----------------------------------------------|------------|
| 1 | `netmiko/nokia/nokia_sros.py:67` | `NokiaSrosSSH` | `\*?(.*?)(>.*)*#` | **Exponential** |
| 2 | `netmiko/nokia/nokia_isam.py:25` | `NokiaIsamSSH` | `\*?(.*?)(>.*)*#` | **Exponential** |
| 3 | `netmiko/extreme/extreme_exos.py:41` | `ExtremeExosBase` | `[\*\s]*(.*)\.\d+` | Polynomial (~O(n³)) |
| 4 | `netmiko/cisco/cisco_asa_ssh.py:116` | `CiscoAsaSSH` | `(.*)\(conf.*` | Polynomial (~O(n²)) |

All four share the pattern:
```python
def set_base_prompt(self, *args, **kwargs) -> str:
    cur_base_prompt = super().set_base_prompt(*args, **kwargs)   # <- device output
    match = re.search(<regex>, cur_base_prompt)                  # <- backtracks
    if match:
        self.base_prompt = match.group(1)
    ...
```

## Why the input is attacker-controlled

`set_base_prompt()` calls `super().set_base_prompt(...)`, which calls
`BaseConnection.find_prompt()` and returns whatever the device emitted as its prompt,
verbatim and **without any length limit**. Anyone controlling the device's returned bytes —
a compromised device, a rogue device during onboarding/inventory, or a MITM on the
SSH/Telnet management stream — controls the regex input. The hang is in pure-Python regex
evaluation, so SSH/read timeouts do not interrupt it.

## Measured impact (proof of concept)

Exact library regexes via `re.search`, CPython 3.13 (see [`poc.py`](poc.py); it opens no
network connections and runs no device commands):

**#1/#2 Nokia — exponential.** Input `">" * n` (a `>`-only prompt, no `#`):

| n (`>` chars) | time |
|--:|--:|
| 20 | 0.21 s |
| 24 | 3.34 s |
| 26 | > 10 s (aborted) |

Each +2 chars ≈ ×4 (`O(2^(n/2))`). A **~30–40 byte** prompt never completes in practice.

**#3 Extreme EXOS — polynomial (~cubic).** Input `" " * n + "!"` (spaces, no `.<digit>`):

| n | time |
|--:|--:|
| 500 | 0.18 s |
| 1000 | 1.56 s |
| 2000 | > 12 s (aborted) |

**#4 Cisco ASA — polynomial (~quadratic).** Input `"a " * n + "!"` (no `(conf`):
blows past 8 s around n≈20,000 characters.

## Severity

**Primary (Nokia #1/#2): Medium, trending High.** CVSS 3.1
`AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` = **6.5**; **7.5 (UI:N)** for unattended collectors
that poll devices on a schedule. Exponential, ~30-byte trigger, reliable.

**Secondary (Extreme #3, Cisco ASA #4): Low–Medium.** Same vector, but polynomial, so the
attacker needs a larger prompt (a few KB → tens of KB) to cause a comparable hang. Still a
valid DoS, especially for #3 (cubic), and worth fixing as part of the class.

Across all four: availability only — no code execution, no data disclosure, no integrity
impact. The one real-world barrier is the precondition (attacker must control a managed
device's returned bytes), which keeps this out of Critical territory. The core expectation
it breaks: a *managed* device should not be able to take down the *manager*.

## How the attack happens (step-by-step)

1. An operator / automation opens a Netmiko session to a Nokia SR-OS/ISAM, Extreme EXOS, or
   Cisco ASA device (`device_type="nokia_sros"`, `"extreme_exos"`, `"cisco_asa"`, …). This
   is intended use; `session_preparation()` calls `set_base_prompt()`.
2. `set_base_prompt()` → `find_prompt()` returns the device's prompt bytes verbatim.
3. A hostile device returns a crafted prompt — e.g. `A:>>>>…>>>` (no `#`) for Nokia, or a few
   thousand spaces/`*` for Extreme, or a long run before `(conf` for ASA.
4. The driver runs `re.search(<evil regex>, cur_base_prompt)`; the engine explores
   super-linearly many ways to match and does not return.
5. The worker/thread doing that session is wedged at 100% CPU; a single-threaded collector is
   fully stalled, blinding the operator and halting automation.

## Suggested remediation (all verified behaviour-preserving + linear)

For normal prompts each replacement captures the **identical** `group(1)` as today, and is
backtracking-free (tested to 100,000+ chars in <5 ms):

```python
# nokia_sros.py:67 and nokia_isam.py:25  — keep hostname before any '>' or '#'
match = re.search(r"\*?([^>#]*)", cur_base_prompt)

# extreme_exos.py:41  — anchored; capture starts non-space; strip trailing '.<digits>'
match = re.search(r"^\*?\s*(\S.*?)\.\d+", cur_base_prompt)

# cisco_asa_ssh.py:116 — anchored, lazy; strip trailing '(conf...'
match = re.search(r"^(.*?)\(conf", cur_base_prompt)
```

General fix principles for this class: anchor the pattern (`^`) so `re.search` does not
re-scan from every offset; avoid a group-quantifier wrapping another quantifier
(`(>.*)*`); and avoid two adjacent quantifiers over overlapping character classes
(`[\*\s]*(.*)`). An explicit prompt-length cap before matching is a useful defence in depth.

Netmiko maintainers already accept prompt-regex fixes of this shape (cf. upstream issue
#3208, a Ciena SAOS prompt-regex fix).

## Disclosure plan (coordinated)

1. **Private report first** to `ktbyers/netmiko` via GitHub "Report a vulnerability".
   Include this analysis (all four sites), the PoC, and the proposed fixes.
2. Offer the fixes as a single PR once acknowledged.
3. Request a CVE through the GitHub advisory / MITRE **after** maintainer coordination and an
   agreed disclosure date (one advisory can cover the cluster).
4. Only then publish this advisory / make any containing repo public.

## Credit

Found by source-code audit + a method-aware automated ReDoS oracle and a package-wide
regex battery test (`scripts/auto_redos2.py`, `scripts/netmiko_audit.py`). See
`../../METHODOLOGY.md` and `../../HUNTING_LOG.md`.
