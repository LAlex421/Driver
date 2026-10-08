# Finding Your Own CVE — Methodology

A practical, repeatable process for discovering a real vulnerability in open-source
software and disclosing it responsibly. Written for a Python / PyPI target, but the
mental model transfers to any ecosystem.

## The mental model: source → sink

A vulnerability is almost always a path from a **source** (attacker-controlled input)
to a **sink** (a dangerous operation) where the input is not properly sanitized along
the way.

- **Sources**: function arguments exposed as public API, CLI arguments, file contents,
  network responses, filenames *inside* an archive, environment variables.
- **Sinks**: operations that execute code, touch the filesystem by path, or run a shell.

## High-value sinks in Python

| Sink | Bug class | Proof-of-concept idea |
|------|-----------|-----------------------|
| `os.system`, `subprocess.*(shell=True)`, `os.popen` | Command injection | inject `; touch /tmp/pwned` |
| `tarfile.extractall` / `TarFile.extract` | Path traversal (tarslip) | archive member named `../../x` |
| `zipfile.extract` / `extractall` | Path traversal (zipslip) | zip entry with `../` or absolute path |
| `yaml.load` without `SafeLoader` | Arbitrary code execution | `!!python/object/apply:os.system` |
| `pickle.loads`, `marshal.loads` | Arbitrary code execution | crafted pickle |
| `eval`, `exec`, `compile` on input | Arbitrary code execution | expression payload |
| `open(path)` with unsanitized path | Path traversal | `../../etc/passwd` |
| `xml.etree` / `lxml` with external entities | XXE | DTD with external entity |
| user-controlled regex, or regex over user input | ReDoS | catastrophic backtracking string |

## The process

1. **Pick a target.** Prefer *small*, *not-recently-audited*, *input-handling* packages
   with real download numbers (so a CVE is worth issuing). Wrappers around shell tools
   and archive handlers are gold.
2. **Get the source.** `pip download --no-deps --no-binary :all: -d ./src <pkg>` then
   unpack the sdist. Read the real source, not the docs.
3. **Grep for sinks.** Search for the patterns in the table above.
4. **Trace back to a source.** For each sink hit, ask: *can attacker-controlled input
   reach this?* If a public function passes its argument into `os.system`, you likely
   have a bug.
5. **Confirm it's not already sanitized.** Read the surrounding code carefully — many
   sinks are guarded. The bug is in the *gap*.
6. **Write a minimal PoC** that proves impact safely (e.g. create a marker file in a
   temp dir — never anything destructive).
7. **Check it's novel.** Search the CVE databases, the project changelog, and the issue
   tracker. If it's already fixed/known, move on.
8. **Disclose responsibly.** Report privately to the maintainer first. Give them time.
   Then request a CVE via GitHub Security Advisories (if hosted on GitHub) or MITRE.

## Responsible disclosure checklist

- [ ] Reported privately to the maintainer / security contact first.
- [ ] Gave a reasonable remediation window (commonly 90 days).
- [ ] PoC demonstrates the flaw without causing real-world harm.
- [ ] Did not test against systems you don't own or have permission to test.
- [ ] Requested CVE through a legitimate channel (GHSA or MITRE CNA).

## What this repo will contain

- `METHODOLOGY.md` — this file.
- `ADVISORY.md` — the writeup of the specific vulnerability we find (template below).
- `poc/` — minimal, safe proof-of-concept.
