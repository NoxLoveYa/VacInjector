"""Fail if new plaintext banned import is added. Phase 08 gate.
Loader-side (injector-core/common/loader) may use LoadLibrary for payload import fixup;
injected code (payload/stealth/sdk) must be hash-only.
CreateRemoteThread is APPROVED as ManualMap-stub executor (remote_thread.cpp, never
LoadLibrary-combo): the image stays unlinked/erased. Only the LoadLibrary COMBO is banned."""
import sys, pathlib
BANNED_STRICT = ["SetWindowsHookEx"]  # banned everywhere
BANNED_COMBO = ["LoadLibrary"]  # banned in EXECUTION paths (remote_thread/apc/hijack/dispatch)
COMBO_ROOTS = [pathlib.Path("src/injector-core/remote_thread.cpp"),
               pathlib.Path("src/injector-core/apc.cpp"),
               pathlib.Path("src/injector-core/thread_hijack.cpp")]
BANNED_INJECTED = ["LoadLibraryA", "LoadLibraryW"]  # banned only in injected code
STRICT_ROOTS = [pathlib.Path("src")]
INJECTED_ROOTS = [pathlib.Path("src/payload"), pathlib.Path("src/stealth"), pathlib.Path("src/sdk")]
import re


def code_only(t):
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    return "\n".join(line.split("//", 1)[0] for line in t.splitlines())


hits = []
for r in STRICT_ROOTS:
    for p in r.rglob("*.cpp"):
        t = code_only(p.read_text(errors="ignore"))
        for b in BANNED_STRICT:
            if b in t:
                hits.append(f"{p}:{b}")
for p in COMBO_ROOTS:
    if not p.exists():
        continue
    t = code_only(p.read_text(errors="ignore"))
    for b in BANNED_COMBO:
        if b in t:
            hits.append(f"{p}:{b}(combo)")
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
