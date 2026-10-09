# Exponential ReDoS in Netmiko Nokia SR-OS / ISAM prompt parsing (`set_base_prompt`)

> **Status: DRAFT — NOT YET DISCLOSED.** This vulnerability appears to be **novel**
> (no CVE or public advisory found as of 2026-10-08). Follow coordinated disclosure:
> report privately to the maintainers **before** making this public or requesting a CVE.
> See "Disclosure plan" below. Do not open a public issue/PR describing the exploit first.

## Summary

Netmiko's Nokia SR-OS and Nokia ISAM connection classes parse the device's command
prompt with a regular expression that exhibits **catastrophic (exponential) backtracking**.
Because the prompt string is derived from data sent by the remote network device, a
**malicious or compromised device** (or an attacker performing MITM on the management
session) can return a short prompt — as few as ~30 bytes — that pins the automation host's
CPU at 100% effectively forever, causing a denial of service on the management/automation
plane.

- **Package:** `netmiko` (PyPI) — a very widely used multi-vendor network-automation library
- **Version analysed:** 4.8.0 (latest at time of writing)
- **Components:**
  - `netmiko/nokia/nokia_sros.py:67` — `NokiaSrosSSH.set_base_prompt`
  - `netmiko/nokia/nokia_isam.py:25` — `NokiaIsamSSH.set_base_prompt`
- **Class:** Uncontrolled resource consumption / ReDoS (CWE-1333, CWE-400)
- **Trigger:** device-controlled prompt output
- **Impact:** CPU exhaustion / denial of service on the host running Netmiko

## The vulnerable regular expression

```python
# netmiko/nokia/nokia_sros.py  (identical in nokia_isam.py)
def set_base_prompt(self, *args, **kwargs) -> str:
    cur_base_prompt = super().set_base_prompt(*args, **kwargs)   # <- device output
    match = re.search(r"\*?(.*?)(>.*)*#", cur_base_prompt)       # <- evil regex
    if match:
        self.base_prompt = match.group(1)
    return self.base_prompt
```

The sub-expression `(>.*)*` nests an unbounded `.*` inside a group that is itself repeated
with `*`, and the inner `.*` can also match `>` characters. On an input that contains a run
of `>` characters and **no terminating `#`**, the engine can partition that run among the
group iterations in exponentially many ways, and tries them all before concluding the match
(here, the surrounding `re.search`) cannot succeed.

## Why the input is attacker-controlled

`set_base_prompt` calls `super().set_base_prompt(...)`, which calls
`BaseConnection.find_prompt()` and returns whatever the device emitted as its prompt. There
is **no length cap or sanitisation** between that device output and the vulnerable
`re.search`. Any party able to control the bytes the device returns — a compromised device,
a malicious device an operator is asked to onboard, or a man-in-the-middle on the
SSH/Telnet management channel — controls the regex input.

In network automation this matters: the management/automation controller is a high-value
host, and a device under management should not be able to wedge it.

## Measured impact (proof of concept)

Input: `">" * n` (a prompt consisting solely of `>` characters), fed to the exact regex via
`re.search`, CPython 3.13:

| n (`>` chars) | time |
|--------------:|-----:|
| 20 | 0.21 s |
| 22 | 0.85 s |
| 24 | 3.34 s |
| 26 | > 10 s (aborted) |

Each additional **two** characters multiplies the running time by ~4 — i.e. `O(2^(n/2))`
exponential blow-up. A ~40-byte prompt will not finish in any practical time. See
[`poc.py`](poc.py) for a self-contained, non-destructive reproduction (it only times the
regex; it opens no network connections and runs no device commands).

### End-to-end reachability (no live device needed to see the path)

`NokiaSrosSSH.set_base_prompt` → `re.search(EVIL, cur_base_prompt)` where
`cur_base_prompt = BaseConnection.find_prompt()` = raw device output. A device returning a
base prompt such as `A:>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>` (no `#`) triggers the hang the next
time Netmiko establishes the session / recomputes the base prompt.

## How the attack happens (step-by-step)

The attacker's goal is to make the operator's automation host run this regex against a
string the attacker controls. The chain:

1. **The operator runs Netmiko against a Nokia device.** This is ordinary, intended use:
   a script, a scheduler (e.g. Nornir/Netmiko, Ansible's `netmiko` modules, a home-grown
   collector) opens a `NokiaSrosSSH` / `NokiaIsamSSH` session — `device_type="nokia_sros"`
   or `"nokia_isam"`. Establishing a session calls `set_base_prompt()` as part of
   `session_preparation()`.
2. **Netmiko reads the device's prompt.** `set_base_prompt()` → `find_prompt()` sends a
   newline and returns whatever the device echoes back as its prompt, **verbatim and with no
   length limit**, as `cur_base_prompt`.
3. **The device returns a malicious prompt.** Instead of a normal prompt like
   `*A:router1>config#`, the attacker-controlled device replies with a short string of `>`
   characters and **no `#`**, e.g. `A:>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>` (~40 bytes).
4. **Netmiko runs the evil regex on it.** `re.search(r"\*?(.*?)(>.*)*#", cur_base_prompt)`
   begins exploring the exponentially many ways to split that `>` run among the `(>.*)*`
   iterations, looking for a trailing `#` that never comes.
5. **The automation host hangs.** One CPU core goes to 100% and the call does not return in
   any practical time. The worker/thread/process doing that session is dead; a single-threaded
   collector is fully wedged, and the SSH session's own timeouts do not help because the hang
   is in pure-Python regex evaluation, not in network I/O.

**Who can be the "malicious device":**
- A device an attacker has already compromised (lateral movement: a foothold on one managed
  router becomes a DoS primitive against the automation controller that polls it).
- A rogue/planted device on a network the operator is asked to onboard or inventory.
- A man-in-the-middle on the management channel (Telnet in clear; SSH if the attacker holds a
  position that lets them tamper with the stream).
- Any scenario where prompt text crosses a trust boundary into the automation host.

## Danger level

**Rating: Medium (CVSS 3.1 ~6.5), trending High in unattended automation.**

Suggested CVSS 3.1 vector: `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` = **6.5 (Medium)**.
- **AV:N** — the trigger arrives over the network connection to the device.
- **AC:L** — crafting the prompt is trivial (a few dozen `>`); the blow-up is deterministic.
- **PR:N** — no credentials on the Netmiko host are needed.
- **UI:R** — in the common case a human/automation must initiate the session to the malicious
  device. In an **unattended collector that polls devices on a schedule, this becomes UI:N**,
  raising the vector to `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 (High)**.
- **A:H** — complete, persistent CPU exhaustion of the affected worker; no auto-recovery.

**What it is not:** no code execution, no data disclosure, no integrity impact. It is purely
availability. The main real-world barrier is the precondition — the attacker must control the
bytes a managed device returns — which is why this is Medium rather than Critical. The
mitigating factors are the precondition only; once met, exploitation is reliable, cheap, and
triggered by ~30–40 bytes.

**Why it still matters:** the automation/management plane is high-value, and a core security
expectation is that a *managed* device cannot take down the *manager*. This breaks that: one
compromised router can hang the controller that oversees the whole fleet, blinding operators
and stalling automated remediation precisely when it is needed.

## Suggested remediation

Replace the ambiguous pattern. The intent is only to strip a leading `*` and keep the
hostname portion before any `>` (config-level suffix) or `#`. That needs no nested
quantifier:

```python
# Linear, same captured hostname for normal prompts like  *A:host>config#
match = re.search(r"\*?([^>#]*)", cur_base_prompt)
if match:
    self.base_prompt = match.group(1)
```

Equivalent alternatives: an atomic group / possessive quantifier (Python 3.11+):
`r"\*?(.*?)(?:>.*)*+#"`, or simply cap the prompt length before matching. The
`[^>#]*` form is the simplest and is backtracking-free.

Verified: for a normal prompt `*A:hostname>config#`, both the original and the proposed
`\*?([^>#]*)` capture `A:hostname` in group(1).

## Disclosure plan (coordinated)

1. **Private report first** to the Netmiko maintainers (`ktbyers/netmiko`) via GitHub's
   "Report a vulnerability" / Security Advisory form — include this analysis, the PoC, and
   the proposed fix.
2. Offer the one-line fix (above) as a PR once the maintainers acknowledge, or let them fix.
3. Request a CVE (GitHub can issue one through the advisory, or via MITRE) **after**
   maintainer coordination / an agreed disclosure date.
4. Only then publish this advisory / make any repo containing it public.

## Credit

Found by independent source code audit + automated ReDoS oracle (see `../../METHODOLOGY.md`
and `../../HUNTING_LOG.md`).
