# huntr submission — Evidently collector unauthenticated arbitrary file write

Paste into huntr's Open Source form (https://huntr.com/bounties/disclose/opensource). Confirm
`evidently` is in scope; if listed, great (it already has CVEs on huntr).

## Form fields
- **Package / registry:** `evidently` (pip / PyPI)
- **Repository:** https://github.com/evidentlyai/evidently
- **Affected version:** 0.7.23 (current); the collector `set_reference` path build is long-standing.
- **Vulnerable file:** `src/evidently/legacy/collector/app.py` — `set_reference` (`to_parquet`
  on `os.path.join(service_workspace, reference_path)`, ~line 95); config field
  `CollectorConfig.reference_path` in `collector/config.py`.
- **Weakness (CWE):** CWE-22 / CWE-73 (external control of file name/path → arbitrary file write).
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` ≈ 9.1 (High/Critical).

## Title
Unauthenticated arbitrary file write via client-controlled `reference_path` in the Evidently collector service

## Description
**Overview.** Evidently's collector HTTP service lets a client create a collector from a
`CollectorConfig` JSON (`POST /{id}`) and then push reference data (`POST /{id}/reference`). In
`set_reference`, the server computes `path = collector.reference_path or f"{id}_reference.parquet"`
and writes `data.to_parquet(os.path.join(service_workspace, path))` with **no path containment
check**. `reference_path` is a client-settable field, so an absolute path (which makes
`os.path.join` discard the workspace) or a `../` sequence writes attacker-controlled parquet
bytes to an arbitrary filesystem path.

**Unauthenticated by default.** `create_app` uses `guards=[is_authenticated]`, but with the
default `run(secret=None)` the service is `NoSecurityService`, whose `authenticate()` always
returns a user → every request is "authenticated". No credentials are needed.

**Steps to reproduce.**
1. `POST /evil` body `{"project_id":"x","reference_path":"/absolute/path/to/victim_file"}`
   (a CollectorConfig; `reference_path` may also be `../../../...`).
2. `POST /evil/reference` with any JSON records (e.g. `{"a":[1,2,3]}`).
3. The server writes a parquet file to the attacker-chosen path.

**PoC.** Attached `poc.py` replicates the exact `set_reference` path computation and shows both
an absolute and a `../` `reference_path` escaping `service_workspace` with a real write
(non-destructive marker files). `to_parquet` is the real sink; the path it receives is identical.

**Impact.** Unauthenticated arbitrary file write → overwrite importable Python modules / config /
cron / autoloaded files → remote code execution; at minimum file corruption/DoS.

## Suggested fix
Validate `reference_path` (reject absolute and `..`; `realpath` must stay within
`service_workspace`), apply the same to all config-derived paths, and require a secret for a
network-exposed collector instead of defaulting to `NoSecurityService`.

## Notes for the reviewer
- Distinct from CVE-2026-75111 (that is a path-traversal **read** in the Evidently **UI**; this is
  a **write** in the **collector**). Independent discovery; prior art checked — no advisory for
  this sink as of 2026-10-09. Please confirm no newer collector advisory supersedes it.
- Severity assumes a network-exposed collector (its intended use); default CLI host is loopback.
- **Discoverer:** <your name / handle>.
