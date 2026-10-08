# Analysis: ReDoS in configobj section-header parsing (5.0.9)

> **Attribution / honesty note.** This is an **independent rediscovery**, written up as a
> learning artifact. The vulnerability was **first publicly reported** in
> [DiffSK/configobj issue #281](https://github.com/DiffSK/configobj/issues/281)
> ("Security: quadratic-time denial of service (ReDoS) in section-header parsing").
> Discovery credit belongs to that reporter. This document does **not** claim an original
> finding and does **not** request a CVE — it records our own analysis, proof-of-concept,
> and proposed fix. It is distinct from
> [CVE-2023-26112](https://cyberstrike.io/cve/CVE-2023-26112/), which affected the
> `validate()` code path.

## Summary

`configobj` compiles a regular expression (`_sectionmarker`) to recognise section-header
lines (`[section]`, `[[subsection]]`, …) and applies it to **every** non-empty, non-comment
line of a configuration file during parsing. The expression backtracks super-linearly on
crafted input, so a single moderately long line can consume seconds-to-minutes of CPU — a
regular-expression denial of service (ReDoS, CWE-1333 / CWE-400).

- **Package:** `configobj`
- **Version analysed:** 5.0.9 (latest at time of writing)
- **Component:** `src/configobj/__init__.py`, `ConfigObj._sectionmarker`
- **Class:** Uncontrolled resource consumption via regular expression (ReDoS)
- **Vector:** Parsing an attacker-influenced configuration file / string
- **Impact:** CPU exhaustion / denial of service

## The vulnerable pattern

```python
_sectionmarker = re.compile(r'''^
    (\s*)                     # 1: indentation
    ((?:\[\s*)+)              # 2: section marker open   <-- nested quantifier
    (                         # 3: section name open
        (?:"\s*\S.*?\s*")|    #    double-quoted
        (?:'\s*\S.*?\s*')|    #    single-quoted
        (?:[^'"\s].*?)        #    unquoted (lazy .*?)
    )
    ((?:\s*\])+)              # 4: section marker close  <-- nested quantifier
    \s*(\#.*)?
    $''', re.VERBOSE)
```

Two features combine to cause catastrophic backtracking:

1. **Nested quantifiers** `((?:\[\s*)+)` and `((?:\s*\])+)` — each `[` (or `]`) can be
   attributed to the group in many ways once the overall match is forced to fail.
2. **A lazy, unanchored name group** `(?:[^'"\s].*?)` sandwiched between them, which lets the
   engine explore an exponential/polynomial number of partitions of the `[`…`]` run before it
   can conclude the line does not match.

When a line starts with many `[`, contains a non-space name, and then fails to close cleanly
(e.g. one `]` short, or a trailing non-bracket character), the regex engine backtracks across
all the ways the opening/closing bracket runs could have been divided.

## Where attacker input reaches it

`src/configobj/__init__.py`, `ConfigObj._parse`:

```python
while cur_index < maxline:
    ...
    line = infile[cur_index]
    sline = line.strip()
    if not sline or sline.startswith('#'):
        continue
    ...
    mat = self._sectionmarker.match(line)   # every content line, no length cap
```

There is **no length limit or pre-filter** before the match, so any caller that parses a
configuration file whose contents can be influenced by an attacker is exposed. This is common:
web apps that accept uploaded/edited `.ini`-style config, multi-tenant services, CI systems
that read user-supplied config, etc.

## Measured impact (proof of concept)

Payload: a single line of the form `"[" * n + "x" + "]" * (n-1) + "!"`.

Driven through the **public API** (`ConfigObj(payload.splitlines())`) on CPython 3.13:

| n (brackets) | line length | parse time |
|-------------:|------------:|-----------:|
| 100 | 201 | 0.05 s |
| 200 | 401 | 0.42 s |
| 400 | 801 | 3.57 s |
| 800 | 1601 | **26.98 s** |

Each doubling of the input multiplies parse time by roughly 8×, i.e. super-linear
(≈ cubic) growth. A line of a few thousand characters pushes parse time into minutes. The
raw regex alone shows the same curve (see `poc/`).

See [`poc/configobj_redos_poc.py`](poc/configobj_redos_poc.py) for a self-contained,
non-destructive reproduction (it only times parsing; it writes nothing and runs no external
commands).

## Suggested remediation

Any one of these mitigates it; the first two are the robust fixes:

1. **Bound the bracket runs.** Replace the unbounded nested quantifiers with simple,
   non-nested matches of the bracket run and count depth in code, e.g. match
   `^(\s*)(\[+)\s*(.*?)\s*(\]+)\s*(#.*)?$` and validate/strip inside `_parse` instead of
   letting the regex attribute each bracket. A non-nested `\[+` / `\]+` cannot backtrack
   across partitions.
2. **Cap line length** before matching (reject or refuse to parse lines beyond a sane limit,
   e.g. a few KB), turning any residual blow-up into O(1).
3. **Defense in depth for callers:** size-limit untrusted config and/or parse under a
   timeout / separate process.

## Lessons (methodology)

- A static "dangerous shape" scan flags *candidates*; only **timing** separates a real ReDoS
  from a false positive. Three of our four flagged regexes were linear.
- Always confirm the sink is reachable from a realistic **source** (here, every content line),
  with no length cap in between.
- Before claiming a finding, **search prior art** (CVE databases, issue trackers, changelogs).
  This bug was already reported as issue #281 — check first, claim honestly.
