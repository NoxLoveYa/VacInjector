"""Fail if new plaintext banned import is added. Phase 08 gate.
Loader-side (injector-core/common/loader) may use LoadLibrary for payload import fixup;
injected code (payload/stealth/sdk) must be hash-only."""
import sys, pathlib
BANNED_STRICT = ["CreateRemoteThread", "SetWindowsHookEx"]  # banned everywhere
BANNED_INJECTED = ["LoadLibraryA", "LoadLibraryW"]  # banned only in injected code
STRICT_ROOTS = [pathlib.Path("src")]
INJECTED_ROOTS = [pathlib.Path("src/payload"), pathlib.Path("src/stealth"), pathlib.Path("src/sdk")]
hits = []
for r in STRICT_ROOTS:
    for p in r.rglob("*.cpp"):
        t = p.read_text(errors="ignore")
        for b in BANNED_STRICT:
            if b in t:
                hits.append(f"{p}:{b}")
for r in INJECTED_ROOTS:
    for p in r.rglob("*.cpp"):
        if not p.exists(): continue
        t = p.read_text(errors="ignore")
        for b in BANNED_INJECTED:
            if b in t and "hash" not in t.lower():
                hits.append(f"{p}:{b}")
print("banned import check:", "FAIL" if hits else "OK")
for h in hits: print(h)
sys.exit(1 if hits else 0)
