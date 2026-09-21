#include "injector_core.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>

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
// v4: stub-only RX alloc on the thread's OWN stack (TEB-consistent) + HUNT.
// SetThreadContext on a thread parked inside a syscall is discarded by the kernel
// on wait completion, so: per candidate TID set ctx, resume 30ms, re-suspend and check
// RIP stuck in stub. Only a stuck thread runs the stub; others are restored untouched.
// Stuck thread gets a short flag poll (DllMain runs in ms when it runs at all).
static bool HijackX64(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err) {
  DWORD pid = GetProcessId(hProc);
  DWORD tids[64]; int nTids = 0;
  {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { err = "thread snap failed"; return false; }
    THREADENTRY32 te{ sizeof(te) };
    for (BOOL ok = Thread32First(snap, &te); ok && nTids < 64; ok = Thread32Next(snap, &te))
      if (te.th32OwnerProcessID == pid) tids[nTids++] = te.th32ThreadID;
    CloseHandle(snap);
  }
  if (!nTids) { err = "no threads found"; return false; }

  // Layout: stub page [base, base+4K) -> RX; data page [base+4K, base+8K) stays RW.
  // (VirtualProtect is page-granular: protecting "128 bytes" RX would also seal a
  // same-page flag and AV on write. Separate pages avoid it.)
  // Stub writes STAGE=1 on entry, calls DllMain, writes FLAG=1, spins.
  // Postmortem: stage==0 never ran; stage==1&&flag==0 DllMain hung/faulted.
  const SIZE_T kTotal = 0x2000;
  const SIZE_T kStageOff = 0x1000, kFlagOff = 0x1004;
  void* remote = VirtualAllocEx(hProc, nullptr, kTotal, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { err = "hijack alloc failed"; return false; }
  uintptr_t stubAddr = (uintptr_t)remote;
  uintptr_t stageAddr = stubAddr + kStageOff;
  uintptr_t flagAddr = stubAddr + kFlagOff;

  uint8_t stub[57] = {
    0xC7, 0x05, 0,0,0,0, 0x01,0,0,0, // 0: mov dword [STAGE],1
    0x48, 0xB9, 0,0,0,0,0,0,0,0,     // 10: mov rcx, hMod
    0xBA, 0x01,0,0,0,                 // 20: mov edx, 1
    0x4D, 0x31, 0xC0,                 // 25: xor r8, r8
    0x48, 0x83, 0xEC, 0x28,           // 28: sub rsp, 0x28
    0x48, 0xB8, 0,0,0,0,0,0,0,0,     // 32: mov rax, DllMain
    0xFF, 0xD0,                       // 42: call rax
    0x48, 0x83, 0xC4, 0x28,           // 44: add rsp, 0x28
    0xC6, 0x05, 0,0,0,0, 0x01,        // 48: mov byte [FLAG],1
    0xEB, 0xFE                        // 55: jmp $
  };
  bool noCall = (getenv("VACSAFE_NOCALL") != nullptr);
  int32_t d1 = (int32_t)(stageAddr - (stubAddr + 10));
  memcpy(stub + 2, &d1, 4);
  if (noCall) {
    stub[42] = 0x90; stub[43] = 0x90; // DIAG: skip call, prove run-to-completion
  } else {
    memcpy(stub + 12, &arg, 8);
    memcpy(stub + 34, &entry, 8);
  }
  int32_t d2 = (int32_t)(flagAddr - (stubAddr + 48 + 7));
  memcpy(stub + 48 + 2, &d2, 4);

  SIZE_T wStub = 0, wData = 0; uint64_t zero = 0;
  BOOL wok1 = WriteProcessMemory(hProc, (LPVOID)stubAddr, stub, sizeof(stub), &wStub);
  BOOL wok2 = WriteProcessMemory(hProc, (LPVOID)stageAddr, &zero, sizeof(zero), &wData);
  if (!wok1 || wStub != sizeof(stub) || !wok2) {
    err = "hijack stub write failed"; VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); return false;
  }
  DWORD old = 0;
  VirtualProtectEx(hProc, (LPVOID)stubAddr, 0x1000, PAGE_EXECUTE_READ, &old);

  ULONGLONG deadline = GetTickCount64() + timeoutMs;
  bool verbose = (getenv("VACSAFE_VERBOSE") != nullptr);
  std::string lastErr = "no hijackable thread (all parked in syscalls)";
  // Try each TID up to 3 stick attempts; per stuck thread poll flag up to 1200ms.
  for (int ti = 0; ti < nTids; ++ti) {
    if ((LONG64)(deadline - GetTickCount64()) <= 500) break;
    DWORD chosen = tids[ti];
    HANDLE hTh = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, chosen);
    if (!hTh) continue;
    CONTEXT orig{}; bool haveOrig = false;

    for (int attempt = 0; attempt < 3; ++attempt) {
      if ((LONG64)(deadline - GetTickCount64()) <= 500) break;
      if (SuspendThread(hTh) == (DWORD)-1) break;
      CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
      if (!GetThreadContext(hTh, &ctx)) { ResumeThread(hTh); break; }
      if (!haveOrig) { orig = ctx; haveOrig = true; }
      uintptr_t newRsp = (((uintptr_t)ctx.Rsp - 96) & ~(uintptr_t)0xF) + 8;
      ctx.Rip = stubAddr;
      ctx.Rsp = newRsp;
      if (!SetThreadContext(hTh, &ctx)) { ResumeThread(hTh); break; }
      ResumeThread(hTh);
      Sleep(30);
      // Stick check: re-suspend, is RIP ours?
      if (SuspendThread(hTh) == (DWORD)-1) break;
      CONTEXT cur{}; cur.ContextFlags = CONTEXT_CONTROL;
      bool stuck = false;
      if (GetThreadContext(hTh, &cur)) {
        uintptr_t rip = (uintptr_t)cur.Rip;
        stuck = (rip >= stubAddr && rip < stubAddr + 80);
        if (verbose) printf("[hijack] tid=%lu try=%d rip=%p %s\n",
          (unsigned long)chosen, attempt, (void*)rip, stuck ? "STUCK" : "discarded");
      }
      ResumeThread(hTh);
      if (!stuck) {
        // Kernel discarded redirect (thread was in syscall). Restore + retry/next.
        SuspendThread(hTh);
        SetThreadContext(hTh, &orig);
        ResumeThread(hTh);
        Sleep(40);
        continue;
      }
      // Redirect stuck: poll flag briefly. DllMain signals in ms when it runs.
      ULONGLONG pollEnd = GetTickCount64() + 1200;
      bool done = false;
      int sample = 0;
      while (GetTickCount64() < pollEnd && GetTickCount64() < deadline) {
        Sleep(50);
        uint8_t f = 0; SIZE_T r = 0;
        if (ReadProcessMemory(hProc, (LPCVOID)flagAddr, &f, 1, &r) && r == 1 && f == 1) { done = true; break; }
        if (verbose && !done && (++sample == 6 || sample == 14)) {
          // Where is it parked? Resolve RIP -> target module.
          if (SuspendThread(hTh) != (DWORD)-1) {
            CONTEXT pc{}; pc.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hTh, &pc)) {
              uintptr_t rip = (uintptr_t)pc.Rip;
              HMODULE mods[256]; DWORD need = 0;
              char modName[260] = "?";
              if (EnumProcessModules(hProc, mods, sizeof(mods), &need)) {
                for (DWORD i = 0; i < need / sizeof(HMODULE); ++i) {
                  MODULEINFO mi{};
                  if (GetModuleInformation(hProc, mods[i], &mi, sizeof(mi)) &&
                      rip >= (uintptr_t)mi.lpBaseOfDll && rip < (uintptr_t)mi.lpBaseOfDll + mi.SizeOfImage) {
                    GetMappedFileNameA(hProc, (LPVOID)rip, modName, sizeof(modName));
                    const char* base = strrchr(modName, '\\');
                    printf("[hijack] parked rip=%p mod=%s\n", (void*)rip, base ? base + 1 : modName);
                    break;
                  }
                }
              } else {
                printf("[hijack] parked rip=%p (EnumProcessModules GLE=%lu)\n", (void*)rip, GetLastError());
              }
            }
            ResumeThread(hTh);
          }
        }
      }
      // Restore original context regardless, reset flag for next candidate.
      SuspendThread(hTh);
      if (verbose && !done) {
        uint8_t snap[64]{}; SIZE_T rr = 0;
        uint32_t stage = 0xCCCCCCCC; SIZE_T sr = 0;
        uint8_t fb = 0xCC; SIZE_T fr = 0;
        BOOL ok = ReadProcessMemory(hProc, (LPCVOID)stubAddr, snap, sizeof(snap), &rr);
        ReadProcessMemory(hProc, (LPCVOID)stageAddr, &stage, 4, &sr);
        ReadProcessMemory(hProc, (LPCVOID)flagAddr, &fb, 1, &fr);
        printf("[hijack] postmortem stage=%u flag=%u s0=%02X s42=%02X s43=%02X\n",
               stage, fb, snap[0], snap[42], snap[43]);
      }
      SetThreadContext(hTh, &orig);
      ResumeThread(hTh);
      CloseHandle(hTh);
      VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
      if (done) return true;
      err = "exec timeout (E_EXEC_TIMEOUT): DllMain did not signal completion";
      return false; // stuck but DllMain never signaled: don't spray other threads
    }
    if (haveOrig) { SuspendThread(hTh); SetThreadContext(hTh, &orig); ResumeThread(hTh); }
    CloseHandle(hTh);
    lastErr = "redirect discarded (thread in syscall)";
  }
  VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
  err = std::string("exec timeout (E_EXEC_TIMEOUT): ") + lastErr;
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
