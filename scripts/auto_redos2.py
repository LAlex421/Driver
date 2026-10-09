#!/usr/bin/env python3
"""ReDoS oracle v2 — method-aware, richer attacks.

For each regex literal, record which re.* method the call site uses. Test with the
matching behavior:
  - scanning methods (search/sub/subn/findall/finditer): super-linear growth here is a
    genuine DoS, because scanning the whole input IS what the victim does.
  - anchored methods (match/fullmatch): test under fullmatch; only TRUE exponential/high
    polynomial ambiguity blows up, so this avoids the search-start-offset artifact.
Each hit still needs manual confirmation of reachability + prior art.
"""
import ast, os, re, signal, sys, time

SCAN = {"search", "sub", "subn", "findall", "finditer"}
ANCHOR = {"match", "fullmatch"}
ALL = SCAN | ANCHOR | {"compile"}
NESTED = re.compile(r"\([^()]*[+*?][^()]*\)[+*]|\((?:\\?.)\|(?:\\?.)\)[+*]")


def literals(src):
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if (isinstance(f, ast.Attribute) and f.attr in ALL
                    and isinstance(f.value, ast.Name) and f.value.id == "re" and node.args):
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    verbose = any(isinstance(a, ast.Attribute) and a.attr in ("VERBOSE", "X")
                                  for a in node.args[1:])
                    yield node.lineno, a0.value, verbose, f.attr


class Timeout(Exception):
    pass


def guard(sec):
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Timeout()))
    signal.setitimer(signal.ITIMER_REAL, sec)


# one-sided and two-sided pump seeds: (left_unit, right_unit, terminator)
UNITS = ["a", " ", "\t", "1", "a ", ".", "-", "/", "@", "=", "x=", 'a"', "a,", ":", "\\", "%", "a\n"]
TWO_SIDED = [("[", "]"), ("(", ")"), ("{", "}"), ("<", ">"), ('"', '"'), ("a", "!")]
TERMS = ["!", "\x00", " ", "\n", "Z", "]"]


def run(rx, method, s, limit=4.0):
    fn = rx.fullmatch if method in ANCHOR or method == "compile" else getattr(rx, method)
    guard(limit)
    t0 = time.perf_counter()
    try:
        if method in ("sub", "subn"):
            fn("", s)
        else:
            fn(s)
    finally:
        dt = time.perf_counter() - t0
        signal.setitimer(signal.ITIMER_REAL, 0)
    return dt


def test(pattern, verbose, method):
    try:
        rx = re.compile(pattern, re.VERBOSE if verbose else 0)
    except re.error:
        return None
    attacks = []
    for u in UNITS:
        for t in TERMS:
            attacks.append((u, "", t))
    for l, r in TWO_SIDED:
        for t in TERMS:
            attacks.append((l, r, t))
    for lu, ru, term in attacks:
        times = []
        try:
            for n in (1000, 2000, 4000):
                s = lu * n + "x" + ru * n + term
                times.append(run(rx, method, s))
        except Timeout:
            return (f"{lu!r}*n+x+{ru!r}*n+{term!r}", ">4s@n>=1000", method)
        except Exception:
            continue
        if times[-1] > 0.25 and times[-1] > times[0] * 5:
            return (f"{lu!r}*n+x+{ru!r}*n+{term!r}", f"{times[0]:.3f}->{times[-1]:.3f}s", method)
    return None


def main(root):
    seen = set()
    for dp, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".py") or "/test" in dp or fn == "setup.py":
                continue
            p = os.path.join(dp, fn)
            try:
                src = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for lineno, pat, verbose, method in literals(src):
                if len(pat) < 6 or not NESTED.search(pat):
                    continue
                if (pat, method) in seen:
                    continue
                seen.add((pat, method))
                res = test(pat, verbose, method)
                if res:
                    atk, growth, meth = res
                    rel = p.split("/unpack/", 1)[-1]
                    print(f"[{meth}] {rel}:{lineno} ({growth}) attack={atk}")
                    print(f"    {pat!r}\n", flush=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
