# Driver — vulnerability research notes

A small, honest security-research repo: the method I use to find vulnerabilities in
open-source software, plus write-ups of what I find.

## Contents

- **[`METHODOLOGY.md`](METHODOLOGY.md)** — the source→sink method, high-value sink patterns,
  and a responsible-disclosure checklist.
- **[`ADVISORY.md`](ADVISORY.md)** — analysis of a ReDoS in `configobj` 5.0.9's section-header
  parser. An **independent rediscovery** of
  [DiffSK/configobj#281](https://github.com/DiffSK/configobj/issues/281); credit for the
  original report belongs to that reporter (see the attribution note in the file).
- **[`poc/`](poc/)** — self-contained, non-destructive proof-of-concept code.
- **[`advisories/netmiko-prompt-redos/`](advisories/netmiko-prompt-redos/)** — an
  **independently discovered, novel** ReDoS **cluster** in `netmiko` 4.8.0's device-prompt
  parsing (`set_base_prompt` in the Nokia SR-OS/ISAM, Extreme EXOS, and Cisco ASA drivers). **DRAFT / embargoed:** not yet disclosed to maintainers —
  do a private security report before publishing or requesting a CVE.

- **[`advisories/pandasai-sandbox-escape/`](advisories/pandasai-sandbox-escape/)** — a
  fully-working **RCE** sandbox-escape PoC against PandasAI 2.3.2. Clearly labeled: this is a
  **reproduction of the known CVE-2024-12366** (PandasAI ≤2.4.3), **not** an original find —
  kept as a demonstration of RCE-class analysis. Prior art was checked before any claim.

- **[`advisories/shapash-dashboard-rce/`](advisories/shapash-dashboard-rce/)** — a **novel, unauthenticated RCE** in the Shapash ML-explainability web dashboard (`eval()` on a client-controlled Dash callback id, `smart_app.py:2997`). Verified end-to-end. **DRAFT / embargoed** — report via huntr / MAIF before any public mention.

## Ethics

Everything here follows responsible-disclosure norms: findings are confirmed with minimal,
safe PoCs; prior art is checked before any claim; and credit is given to original reporters.
Nothing here is presented as an original discovery unless it genuinely is.
