#!/usr/bin/env python3
"""AST taint scanner for command-injection and unsafe-extraction sinks.

Reads package source as TEXT only (never imports). Flags functions where a
PARAMETER flows into a shell sink via string interpolation (f-string / % / .format
/ concatenation), and unguarded tarfile.extractall/extract without filter=.

Heuristic — every hit must be manually confirmed. Designed for precision over recall.
"""
import ast
import os
import sys


def fstring_names(node):
    """Yield Name ids referenced inside an f-string / format / % / concat expr."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            yield n.id


def is_shell_sink(call):
    """Return a tag if `call` is a shell-executing sink, else None."""
    f = call.func
    # os.system(...) / os.popen(...)
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        if f.value.id == "os" and f.attr in ("system", "popen"):
            return f"os.{f.attr}"
        if f.value.id in ("subprocess",) and f.attr in (
            "call", "run", "Popen", "check_call", "check_output", "getoutput", "getstatusoutput"):
            # only a sink if shell=True
            for kw in call.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return f"subprocess.{f.attr}(shell=True)"
    # commands.getoutput
    if isinstance(f, ast.Name) and f.id in ("system", "popen"):
        return f.id
    return None


def dynamic_arg(call, sink_tag):
    """Return the AST node of the command argument that is built dynamically."""
    if not call.args:
        return None
    a0 = call.args[0]
    # dynamic = f-string, %/+ binop, or .format() call, or a Name (var) we can't easily prove
    if isinstance(a0, ast.JoinedStr):
        return a0
    if isinstance(a0, ast.BinOp) and isinstance(a0.op, (ast.Mod, ast.Add)):
        return a0
    if isinstance(a0, ast.Call) and isinstance(a0.func, ast.Attribute) and a0.func.attr == "format":
        return a0
    return None


def scan_file(path, src):
    hits = []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return hits
    # map function -> set of param names
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = set()
        for a in list(fn.args.args) + list(fn.args.posonlyargs) + list(fn.args.kwonlyargs):
            params.add(a.arg)
        if fn.args.vararg:
            params.add(fn.args.vararg.arg)
        if fn.args.kwarg:
            params.add(fn.args.kwarg.arg)
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            # --- shell sinks ---
            tag = is_shell_sink(node)
            if tag:
                darg = dynamic_arg(node, tag)
                if darg is not None:
                    used = set(fstring_names(darg))
                    tainted = used & params
                    if tainted:
                        hits.append((node.lineno, "CMDI", tag, f"{fn.name}() params={sorted(tainted)}"))
            # --- unguarded tar extraction ---
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in ("extractall", "extract"):
                has_filter = any(kw.arg == "filter" for kw in node.keywords)
                if not has_filter:
                    # crude: is it a tar object? look for 'tar' in the receiver chain text
                    recv = ast.dump(f.value)
                    if "tar" in recv.lower() or f.attr == "extractall":
                        hits.append((node.lineno, "EXTRACT", f".{f.attr}(no filter)", fn.name + "()"))
    return hits


def main(root):
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            if "/test" in p or p.endswith("setup.py") or "/vendor/" in p:
                continue
            try:
                src = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for lineno, kind, tag, where in scan_file(p, src):
                rel = p.split("/unpack/", 1)[-1]
                print(f"[{kind}] {rel}:{lineno}  {tag}  in {where}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
