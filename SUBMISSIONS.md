# Submissions — what to send, where, in what order

Everything is embargoed in this **private** repo. Do not make anything public (issue / PR /
post) until the platform/maintainer coordinates a fix. Attach the named `poc.py` with each
report. Add your name/handle where a report says `<your name / handle>`.

---

## ✅ SUBMIT THESE (novel, verified, yours)

### 1. shapash — unauthenticated RCE  ·  **primary, highest value**
- **Where:** huntr → https://huntr.com (search/add package `shapash`). If not in scope, use the
  MAIF GitHub private advisory (below).
- **Paste:** [`advisories/shapash-dashboard-rce/HUNTR_REPORT.md`](advisories/shapash-dashboard-rce/HUNTR_REPORT.md)
- **Attach:** `advisories/shapash-dashboard-rce/poc.py` · optional fix: `fix.patch`
- **What:** `eval()` on a client-controlled Dash callback id (`smart_app.py:2997`) → unauth RCE.
- **Affected:** 2.2.0 – 2.9.0 (latest), no fix. **CWE-95 · CVSS 9.8.**
- **Backup channel:** MAIF/shapash → https://github.com/MAIF/shapash → Security → Report a
  vulnerability. Full write-up: `advisories/shapash-dashboard-rce/ADVISORY.md`; steps:
  `DISCLOSURE.md`.
- [ ] huntr account created  [ ] shapash in scope confirmed  [ ] report pasted + PoC attached
  [ ] handle filled in  [ ] submitted

### 2. taipy-gui — unauthenticated pandas-query injection + ReDoS  ·  solid
- **Where:** huntr (package `taipy-gui` / `taipy`). If not in scope → Avaiga GitHub advisory:
  https://github.com/Avaiga/taipy → Security → Report a vulnerability.
- **Paste:** [`advisories/taipy-gui-query-injection/HUNTR_REPORT.md`](advisories/taipy-gui-query-injection/HUNTR_REPORT.md)
- **Attach:** `advisories/taipy-gui-query-injection/poc.py`
- **What:** client `filters` payload (WebSocket `DATA_UPDATE`) flows into `df.query` with raw
  `action`/`col`; `contains` passes a client regex → filter bypass, blind data exfiltration,
  ReDoS. Full write-up: `ADVISORY.md`.
- **Affected:** 3.0.0 – 4.0.2 (latest), no fix. **CWE-943/74 + CWE-1333 · CVSS ~9.1** (be
  honest in the report: RCE not demonstrated; reviewer may land it High/Medium).
- [ ] in scope confirmed  [ ] report pasted + PoC attached  [ ] handle filled in  [ ] submitted

### 3. evidently — unauthenticated arbitrary file write (collector)  ·  solid
- **Where:** huntr (package `evidently`; it already has CVEs on huntr). Form:
  https://huntr.com/bounties/disclose/opensource
- **Paste:** [`advisories/evidently-collector-file-write/HUNTR_REPORT.md`](advisories/evidently-collector-file-write/HUNTR_REPORT.md)
- **Attach:** `advisories/evidently-collector-file-write/poc.py`
- **What:** collector `set_reference` writes `to_parquet(join(workspace, reference_path))` with a
  client-controlled `reference_path` (absolute/`../`) and no containment check; unauthenticated by
  default (`NoSecurityService`). Arbitrary file write → potential RCE. Full write-up: `ADVISORY.md`.
- **Affected:** 0.7.23 (current). **CWE-22/73 · CVSS ~9.1.** Honesty: distinct from CVE-2026-75111
  (that's a UI *read*); confirm no newer collector advisory supersedes it, and note the default
  loopback host vs the collector's exposed-by-design use.
- [ ] in scope confirmed  [ ] report pasted + PoC attached  [ ] handle filled in  [ ] submitted

### 4. netmiko — prompt-parsing ReDoS cluster  ·  NOT huntr (not AI/ML)
- **Where:** NOT huntr. Report to the maintainer: ktbyers/netmiko →
  https://github.com/ktbyers/netmiko → Security → Report a vulnerability (GitHub can assign a
  CVE). This earns a **CVE, not a bounty**.
- **Paste:** [`advisories/netmiko-prompt-redos/DISCLOSURE_REPORT.md`](advisories/netmiko-prompt-redos/DISCLOSURE_REPORT.md)
- **Attach:** `advisories/netmiko-prompt-redos/poc.py`
- **What:** exponential/polynomial ReDoS in `set_base_prompt` across Nokia SR-OS/ISAM, Extreme
  EXOS, Cisco ASA drivers on device-controlled prompt output. Full write-up: `ADVISORY.md`.
- **Affected:** netmiko 4.8.0 (and earlier with these drivers). **CWE-1333 · CVSS 6.5–7.5.**
- [ ] report pasted + PoC attached  [ ] handle filled in  [ ] submitted

---

## 🚫 DO NOT SUBMIT (real, but already public — would be rejected as duplicates)

These are kept as portfolio / methodology artifacts only. Submitting them risks dinging your
huntr standing for duplicates.

- **pandasai** sandbox-escape RCE — reproduction of **CVE-2024-12366** (PandasAI ≤2.4.3).
  `advisories/pandasai-sandbox-escape/ANALYSIS.md`.
- **configobj** section-header ReDoS — already reported upstream as **DiffSK/configobj#281**.
  Root `ADVISORY.md` + `poc/configobj_redos_poc.py`.
- **gguf** `GGUFReader` allocation DoS — verified, but the GGUF python-parser DoS class is
  already disclosed (oss-sec 2026-q2/546 names `gguf_reader.py`; multiple CVEs). See
  `HUNTING_LOG.md` round 10.

---

## Order of operations
1. Create the huntr account (Stripe KYC only triggers on first payout; Portugal supported).
2. Submit **shapash** first (strongest), then **taipy-gui**.
3. Submit **netmiko** to its maintainer separately (CVE track, not huntr).
4. Keep everything embargoed until each is coordinated/fixed.
5. Realistic money (both huntr items): roughly **$300–$1,500 combined**, possibly $0 cash + CVEs
   if the packages aren't in funded pools. The durable value is the **CVE credits**.
