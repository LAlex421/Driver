#!/usr/bin/env python3
"""Deep ReDoS audit of ALL regexes in a package (netmiko).

AST-extract every re.* literal + the method used, then battery-test each pattern under
its real method against many attack strings, with an alarm guard. Report super-linear.
No NESTED prefilter — tests everything.
"""
import ast, os, re, signal, sys, time

SCAN = {"search", "sub", "subn", "findall", "finditer"}
ANCHOR = {"match", "fullmatch"}
ALL = SCAN | ANCHOR | {"compile"}


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


UNITS = ["a", " ", "\t", "*", ">", "<", "#", ".", "-", "=", ":", "/", "\\", '"', "'",
         "a ", "a>", "*a", ">a", "a.", "0", "a0", "(", ")", "[", "]", "{", "}", "|", "&", "%s", "a\n"]
TERMS = ["!", "\x00", " ", "\n", "Z", "#", ">"]


def run(rx, method, s, limit):
    fn = rx.fullmatch if (method in ANCHOR or method == "compile") else getattr(rx, method)
    guard(limit)
    t0 = time.perf_counter()
    try:
        fn("", s) if method in ("sub", "subn") else fn(s)
    finally:
        dt = time.perf_counter() - t0
        signal.setitimer(signal.ITIMER_REAL, 0)
    return dt


def test(pattern, verbose, method):
    try:
        rx = re.compile(pattern, re.VERBOSE if verbose else 0)
    except re.error:
        return None
    for u in UNITS:
        for t in TERMS:
            times = []
            try:
                for n in (1000, 2000, 4000):
                    times.append(run(rx, method, u * n + t, 4.0))
            except Timeout:
                return (f"{u!r}*n+{t!r}", ">4s", method)
            except Exception:
                break
            if len(times) == 3 and times[-1] > 0.25 and times[-1] > times[0] * 5:
                return (f"{u!r}*n+{t!r}", f"{times[0]:.3f}->{times[-1]:.3f}s", method)
    # also two-sided for a few bracket/angle pairs
    for l, r in [(">", ""), ("*", ""), ("(", ")"), ("[", "]"), ("a", ">")]:
        for t in TERMS:
            times = []
            try:
                for n in (500, 1000, 2000):
                    times.append(run(rx, method, l * n + "x" + r * n + t, 4.0))
            except Timeout:
                return (f"{l!r}*n+x+{r!r}*n+{t!r}", ">4s", method)
            except Exception:
                break
            if len(times) == 3 and times[-1] > 0.25 and times[-1] > times[0] * 5:
                return (f"{l!r}*n+x+{r!r}*n+{t!r}", f"{times[0]:.3f}->{times[-1]:.3f}s", method)
    return None


def main(root):
    seen = set()
    for dp, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".py") or "/test" in dp:
                continue
            p = os.path.join(dp, fn)
            try:
                src = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for lineno, pat, verbose, method in literals(src):
                if len(pat) < 4 or (pat, method) in seen:
                    continue
                seen.add((pat, method))
                res = test(pat, verbose, method)
                if res:
                    atk, growth, meth = res
                    rel = os.path.relpath(p, root)
                    print(f"[{meth}] {rel}:{lineno} ({growth}) attack={atk}\n    {pat!r}\n", flush=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
