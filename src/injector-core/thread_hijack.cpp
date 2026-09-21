#include "injector_core.h"
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>

namespace vacsafe {

static bool IsTargetX64(HANDLE hProc, bool& out64, std::string& err) {
  BOOL wow = FALSE;
  if (!IsWow64Process(hProc, &wow)) { err = "IsWow64Process failed"; return false; }
#if defined(_WIN64)
  out64 = !wow; // x64 loader: wow=>x86 target
#else
  if (!wow) { err = "x86 loader cannot hijack x64 target (E_ARCH_MISMATCH: use x64 loader)"; return false; }
  out64 = false;
#endif
  return true;
}

#if defined(_WIN64)
static bool HijackX64(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err) {
  DWORD pid = GetProcessId(hProc);
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) { err = "thread snap failed"; return false; }

  DWORD chosen = 0;
  THREADENTRY32 te{ sizeof(te) };
  // Prefer a non-main worker: skip first thread, take second suspendable one.
  DWORD first = 0; int idx = 0;
  for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
    if (te.th32OwnerProcessID != pid) continue;
    if (!first) first = te.th32ThreadID;
    if (idx == 1) { chosen = te.th32ThreadID; break; }
    ++idx;
  }
  if (!chosen) chosen = first;
  CloseHandle(snap);
  if (!chosen) { err = "no threads found"; return false; }

  HANDLE hTh = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, chosen);
  if (!hTh) { char b[96]; snprintf(b, sizeof(b), "OpenThread failed (GLE=0x%08lX)", GetLastError()); err = b; return false; }

  if (SuspendThread(hTh) == (DWORD)-1) { err = "SuspendThread failed"; CloseHandle(hTh); return false; }
  CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(hTh, &ctx)) { err = "GetThreadContext failed"; ResumeThread(hTh); CloseHandle(hTh); return false; }
  CONTEXT orig = ctx;

  DWORD64 origRip = ctx.Rip, origRsp = ctx.Rsp;
  DWORD64 newRsp = (origRsp - 8) & ~(DWORD64)0xF;
  SIZE_T w = 0;
  if (!WriteProcessMemory(hProc, (LPVOID)newRsp, &origRip, sizeof(origRip), &w) || w != sizeof(origRip)) {
    err = "stack push (return addr) failed"; SetThreadContext(hTh, &orig); ResumeThread(hTh); CloseHandle(hTh); return false;
  }
  ctx.Rsp = newRsp;
  ctx.Rcx = (DWORD64)arg;   // hMod
  ctx.Rdx = 1;              // DLL_PROCESS_ATTACH
  ctx.R8 = 0;
  ctx.Rip = (DWORD64)entry; // remote DllMain
  if (!SetThreadContext(hTh, &ctx)) { err = "SetThreadContext failed"; SetThreadContext(hTh, &orig); ResumeThread(hTh); CloseHandle(hTh); return false; }
  ResumeThread(hTh);

  DWORD waited = 0;
  while (waited < timeoutMs) {
    Sleep(50); waited += 50;
    if (SuspendThread(hTh) == (DWORD)-1) break;
    CONTEXT cur{}; cur.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    BOOL ok = GetThreadContext(hTh, &cur);
    DWORD64 rip = ok ? cur.Rip : 0;
    ResumeThread(hTh);
    if (ok && rip == origRip) { CloseHandle(hTh); return true; } // DllMain ret -> back to original RIP
  }
  // Timeout: restore.
  SuspendThread(hTh);
  SetThreadContext(hTh, &orig);
  ResumeThread(hTh);
  CloseHandle(hTh);
  err = "exec timeout (E_EXEC_TIMEOUT): DllMain did not return in time";
  return false;
}
#endif

static bool HijackX86([[maybe_unused]] HANDLE hProc, [[maybe_unused]] void* entry, [[maybe_unused]] void* arg, [[maybe_unused]] DWORD timeoutMs, std::string& err) {
#if defined(_WIN64)
  (void)hProc; (void)entry; (void)arg; (void)timeoutMs;
  err = "x86 hijack needs x86 helper (E_ARCH_MISMATCH: spawn x86 bridge)";
  return false;
#else
  DWORD pid = GetProcessId(hProc);
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) { err = "thread snap failed"; return false; }
  DWORD chosen = 0, first = 0; int idx = 0;
  THREADENTRY32 te{ sizeof(te) };
  for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
    if (te.th32OwnerProcessID != pid) continue;
    if (!first) first = te.th32ThreadID;
    if (idx == 1) { chosen = te.th32ThreadID; break; }
    ++idx;
  }
  if (!chosen) chosen = first;
  CloseHandle(snap);
  if (!chosen) { err = "no threads found"; return false; }
  HANDLE hTh = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, chosen);
  if (!hTh) { err = "OpenThread failed"; return false; }
  if (SuspendThread(hTh) == (DWORD)-1) { err = "SuspendThread failed"; CloseHandle(hTh); return false; }
  CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(hTh, &ctx)) { err = "GetThreadContext failed"; ResumeThread(hTh); CloseHandle(hTh); return false; }
  CONTEXT orig = ctx;
  DWORD origEip = ctx.Eip, origEsp = ctx.Esp;
  DWORD newEsp = origEsp - 16;
  DWORD stack[4] = { origEip, (DWORD)arg, 1, 0 };
  SIZE_T w = 0;
  if (!WriteProcessMemory(hProc, (LPVOID)newEsp, stack, sizeof(stack), &w) || w != sizeof(stack)) {
    err = "stack push failed"; SetThreadContext(hTh, &orig); ResumeThread(hTh); CloseHandle(hTh); return false;
  }
  ctx.Esp = newEsp; ctx.Eip = (DWORD)entry;
  if (!SetThreadContext(hTh, &ctx)) { err = "SetThreadContext failed"; SetThreadContext(hTh, &orig); ResumeThread(hTh); CloseHandle(hTh); return false; }
  ResumeThread(hTh);
  DWORD waited = 0;
  while (waited < timeoutMs) {
    Sleep(50); waited += 50;
    if (SuspendThread(hTh) == (DWORD)-1) break;
    CONTEXT cur{}; cur.ContextFlags = CONTEXT_CONTROL;
    BOOL ok = GetThreadContext(hTh, &cur);
    DWORD eip = ok ? cur.Eip : 0;
    ResumeThread(hTh);
    if (ok && eip == origEip) { CloseHandle(hTh); return true; }
  }
  SuspendThread(hTh); SetThreadContext(hTh, &orig); ResumeThread(hTh);
  CloseHandle(hTh);
  err = "exec timeout (E_EXEC_TIMEOUT)";
  return false;
#endif
}

bool ExecViaHijack(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err) {
  if (!hProc || !entry) { err = "bad args"; return false; }
  bool t64 = false;
  if (!IsTargetX64(hProc, t64, err)) return false;
#if defined(_WIN64)
  (void)&HijackX86; // keep x86 helper linked for WoW64 bridge builds, silence C4505
  if (t64) return HijackX64(hProc, entry, arg, timeoutMs, err);
  err = "x64 loader -> x86 target needs x86 helper (E_ARCH_MISMATCH: spawn x86 bridge)";
  return false;
#else
  if (!t64) return HijackX86(hProc, entry, arg, timeoutMs, err);
  err = "x86 loader cannot inject x64 (E_ARCH_MISMATCH)";
  return false;
#endif
}

} // namespace vacsafe
