# Unauthenticated arbitrary file write (path traversal) in Evidently collector service

> **Status: DRAFT — NOT YET DISCLOSED.** Appears novel for this component (see novelty note).
> Coordinated disclosure via huntr / evidentlyai before any public mention; keep this repo
> private until a fix ships.

## Summary

Evidently is a widely used open-source ML/LLM observability framework. Its **collector**
service (`evidently.legacy.collector.app`, started via `evidently collector` / `run()`) exposes
an HTTP API to receive production data. The `set_reference` endpoint writes a client-supplied
DataFrame to a path built from a **client-controlled `reference_path`** with no containment
check, and the service is **unauthenticated by default**. An attacker can therefore write
attacker-controlled data to an arbitrary filesystem path (absolute or via `../`), i.e.
**unauthenticated arbitrary file write** → potential remote code execution.

- **Package:** `evidently` (PyPI)
- **Version analysed:** 0.7.23 (current). Component: `src/evidently/legacy/collector/app.py`.
- **Class:** Path traversal / external control of file path (CWE-22 / CWE-73), arbitrary file
  write.
- **Auth:** none by default (`run(secret=None)` → `NoSecurityService`).

## Vulnerable code

```python
# evidently/legacy/collector/app.py
@post("/{id:str}")                         # create a collector from a client CollectorConfig
def create_collector(id, parsed_json: CollectorConfig, service, ...):
    parsed_json.id = id
    service.collectors[id] = parsed_json   # attacker controls CollectorConfig.reference_path

@post("/{id:str}/reference")
def set_reference(id, parsed_json, service, service_workspace, ...):
    collector = service.collectors[id]
    data = pd.DataFrame.from_dict(parsed_json)
    path = collector.reference_path or f"{id}_reference.parquet"   # attacker-controlled
    data.to_parquet(os.path.join(service_workspace, path))         # <-- app.py:95, no check
    ...
```

`CollectorConfig.reference_path: Optional[str]` is a plain, client-settable field. `os.path.join`
**discards `service_workspace` when `reference_path` is absolute**, and `../` escapes it
otherwise — so the write lands anywhere the process can write.

## Unauthenticated by default

`create_app` wires `guards=[is_authenticated]`, but:
```python
if secret is None:                       # the DEFAULT for run()/CLI
    security = NoSecurityService(NoSecurityComponent())
# NoSecurityService.authenticate() -> User(id=dummy, name="")   # never None
```
`is_authenticated` only checks `scope["auth"]["authenticated"]`, which `NoSecurityService`
makes `True` for everyone. So with no `--secret`, **all endpoints are open**.

## Attack (unauthenticated)

1. `POST /evil` with body `{"reference_path": "/home/victim/.config/....", "project_id": "x", ...}`
   (a `CollectorConfig`; `reference_path` can be absolute or contain `../`).
2. `POST /evil/reference` with any JSON records → the service runs
   `to_parquet(os.path.join(workspace, reference_path))` → writes attacker parquet bytes to the
   attacker-chosen path.

Escalation to RCE: overwrite a Python module imported by the service, drop a file into an
auto-loaded directory, write a cron/systemd unit (if privileged), poison config, etc. Even
without RCE, arbitrary file write is High severity.

## Proof of concept

[`poc.py`](poc.py) replicates the exact path computation (`set_reference`) and shows both an
absolute and a `../` `reference_path` escaping the workspace with a real write. Output:
`RESULT: VULNERABLE — reference_path controls an out-of-workspace write path`. (The real sink
is `to_parquet`, which writes parquet bytes to that same computed path; the PoC uses a plain
write so no parquet engine is needed.)

## Severity

High. Suggested CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` ≈ **9.1** for a network-exposed,
default-no-secret collector (its intended deployment is to receive data from remote apps). The
CLI default `host` is `127.0.0.1`; a strictly-loopback instance scores lower, but the collector
is designed to be exposed and ships unauthenticated — call this out honestly in the report.

## Remediation

- Reject absolute paths and `..` in `reference_path`; resolve the final path and verify it is
  inside `service_workspace` (e.g. `os.path.realpath(full).startswith(realpath(workspace)+sep)`),
  else 400. Apply the same to any other config-derived path (snapshots, logs).
- Do not default to `NoSecurityService`; require a secret/token for a network service, or bind
  loopback-only and document the risk prominently.

## Novelty note

A **separate** recent CVE, **CVE-2026-75111**, is a path-traversal **file read** in the Evidently
**UI** dataset-materialization endpoint — a different component and a read primitive. This report
is a **write** primitive in the **collector** service via `reference_path`. Evidently is clearly
under active path-traversal review, so confirm no newer advisory already covers the collector
write before/at submission. Prior art checked 2026-10-09: none found for this sink.

## Credit

Independent discovery via web-framework sink scanning (`scripts/hisev_scan.py` + targeted grep)
and verification of the exact path computation.
