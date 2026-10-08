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
- **[`advisories/netmiko-nokia-redos/`](advisories/netmiko-nokia-redos/)** — an
  **independently discovered, novel** exponential ReDoS in `netmiko` 4.8.0's Nokia
  SR-OS / ISAM prompt parsing. **DRAFT / embargoed:** not yet disclosed to maintainers —
  do a private security report before publishing or requesting a CVE.

## Ethics

Everything here follows responsible-disclosure norms: findings are confirmed with minimal,
safe PoCs; prior art is checked before any claim; and credit is given to original reporters.
Nothing here is presented as an original discovery unless it genuinely is.
