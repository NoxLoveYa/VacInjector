"""Fail if new plaintext banned import is added. Phase 08 gate."""
import sys, pathlib
BANNED = ["LoadLibraryA", "LoadLibraryW", "CreateRemoteThread", "SetWindowsHookEx"]
roots = [pathlib.Path("src")]
hits = []
for r in roots:
    for p in r.rglob("*.cpp"):
        t = p.read_text(errors="ignore")
        for b in BANNED:
            if b in t and "hash" not in t.lower():
                hits.append(f"{p}:{b}")
print("banned import check:", "FAIL" if hits else "OK")
for h in hits: print(h)
sys.exit(1 if hits else 0)
