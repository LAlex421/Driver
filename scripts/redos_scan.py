#!/usr/bin/env python3
"""Static ReDoS-shape scanner. Reads package source as TEXT only (never imports it).

Extracts string literals passed to re.* and flags classic catastrophic-backtracking
shapes. Output is a candidate list for manual confirmation via timing.
"""
import ast
import os
import re
import sys

# Dangerous structural signatures (heuristic). These are *candidates*, not proof.
NESTED_QUANT = re.compile(r"\((?:[^()]*[+*])[^()]*\)[+*]")          # (…+…)+  (…*…)*
GROUP_PLUS_PLUS = re.compile(r"\([^()]*\)[+*]\s*[+*]")               # (...)+ +
OVERLAP_ALT = re.compile(r"\((\w|\\[dws])\|\1\)[+*]", re.I)          # (a|a)* (\d|\d)+
QUANT_OVERLAP = re.compile(r"(\\[dsw]|\[[^\]]+\]|\.)[+*]\)?[+*]")    # \s+)+  .*)*

SIGS = [("nested_quant", NESTED_QUANT), ("group++", GROUP_PLUS_PLUS),
        ("overlap_alt", OVERLAP_ALT), ("quant_overlap", QUANT_OVERLAP)]

RE_FUNCS = {"compile", "match", "search", "fullmatch", "sub", "subn", "split", "findall", "finditer"}


def literal_patterns(path, src):
    """Yield (lineno, pattern) for string literals passed as the regex arg to re.*()."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        is_re = (isinstance(f, ast.Attribute) and f.attr in RE_FUNCS and
                 isinstance(f.value, ast.Name) and f.value.id == "re")
        if not is_re or not node.args:
            continue
        a0 = node.args[0]
        if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
            yield node.lineno, a0.value


def main(root):
    hits = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                src = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for lineno, pat in literal_patterns(p, src):
                if len(pat) < 4:
                    continue
                for name, sig in SIGS:
                    if sig.search(pat):
                        hits.append((p, lineno, name, pat))
                        break
    # Dedup and print
    seen = set()
    for p, lineno, name, pat in hits:
        key = (p, lineno, pat)
        if key in seen:
            continue
        seen.add(key)
        rel = p.split("/unpack/", 1)[-1]
        print(f"[{name}] {rel}:{lineno}\n    {pat!r}\n")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
