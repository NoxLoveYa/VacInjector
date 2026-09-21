#include "injector_core.h"
#include <windows.h>
#include <cstdio>
#include <cstring>

namespace vacsafe {
// Fallback when hijack targets are all parked in kernel waits.
// Fresh OS thread: always scheduled, own stack/TEB. Calls mapped DllMain then
// RtlExitUserThread(DllMain retval) so no thread lingers; stub freed after.
// No LoadLibrary involved: image stays ManualMapped (unlinked, headers erased
// payload-side). Thread start in private RX is transient (ms).
#if defined(_WIN64)
static const uint8_t kCrtStub64[] = {
  0x48, 0xB9, 0,0,0,0,0,0,0,0, // 0: mov rcx, hMod
  0xBA, 0x01,0,0,0,             // 10: mov edx, 1
  0x4D, 0x31, 0xC0,             // 15: xor r8, r8
  0x48, 0x83, 0xEC, 0x28,       // 18: sub rsp, 0x28 (entry RSP%16==8 via call)
  0x48, 0xB8, 0,0,0,0,0,0,0,0, // 22: mov rax, DllMain
  0xFF, 0xD0,                   // 32: call rax
  0x48, 0x83, 0xC4, 0x28,       // 34: add rsp, 0x28
  0x48, 0x89, 0xC1,             // 38: mov rcx, rax
  0x48, 0xB8, 0,0,0,0,0,0,0,0, // 41: mov rax, RtlExitUserThread
  0xFF, 0xD0,                   // 51: call rax
  0xCC                          // 53: int3 (unreachable)
};
#endif

bool ExecViaRemoteThread(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err) {
#if !defined(_WIN64)
  err = "CRT x86 path needs x86 helper (E_ARCH_MISMATCH)";
  return false;
#else
  if (!hProc || !entry) { err = "bad args"; return false; }
  BOOL wow = FALSE; IsWow64Process(hProc, &wow);
  if (wow) { err = "x64->x86 CRT needs x86 helper (E_ARCH_MISMATCH)"; return false; }

  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  FARPROC exitFn = ntdll ? GetProcAddress(ntdll, "RtlExitUserThread") : nullptr;
  if (!exitFn) { err = "resolve RtlExitUserThread failed"; return false; }

  void* remote = VirtualAllocEx(hProc, nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { err = "CRT alloc failed"; return false; }
  uintptr_t stubAddr = (uintptr_t)remote;
  uintptr_t stageAddr = stubAddr + 0x1000;

  uint8_t local[64]{}; memcpy(local, kCrtStub64, sizeof(kCrtStub64));
  uintptr_t hMod = (uintptr_t)arg, fn = (uintptr_t)entry, xf = (uintptr_t)exitFn;
  memcpy(local + 2, &hMod, 8);
  memcpy(local + 24, &fn, 8);
  memcpy(local + 43, &xf, 8);
  if (getenv("VACSAFE_CRTNOCALL") != nullptr) {
    local[32] = 0x90; local[33] = 0x90; // DIAG: skip DllMain call; exit code should == entry
  }

  SIZE_T w = 0;
  uint64_t zero = 0;
  BOOL wok1 = WriteProcessMemory(hProc, remote, local, sizeof(kCrtStub64), &w);
  BOOL wok2 = WriteProcessMemory(hProc, (LPVOID)stageAddr, &zero, 8, &w);
  if (!wok1 || !wok2) {
    err = "CRT stub write failed"; VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); return false;
  }
  DWORD old = 0;
  BOOL pok = VirtualProtectEx(hProc, remote, 0x1000, PAGE_EXECUTE_READ, &old);
  if (getenv("VACSAFE_VERBOSE")) {
    MEMORY_BASIC_INFORMATION mbi{};
    VirtualQueryEx(hProc, remote, &mbi, sizeof(mbi));
    printf("[crt] stubProtect=%d stubExec=%s exitFn=%p\n", (int)pok,
           (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE) ? "YES" : "NO",
           exitFn);
  }
  if (!pok) { err = "CRT stub protect RX failed (sandbox blocking exec?)"; VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); return false; }

  HANDLE hTh = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)remote, nullptr, 0, nullptr);
  if (!hTh) {
    char b[96]; snprintf(b, sizeof(b), "CreateRemoteThread failed (GLE=0x%08lX)", GetLastError());
    err = b; VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); return false;
  }
  DWORD wr = WaitForSingleObject(hTh, timeoutMs);
  DWORD code = 0; GetExitCodeThread(hTh, &code);
  CloseHandle(hTh);
  VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
  if (wr != WAIT_OBJECT_0) { err = "CRT thread timeout (E_EXEC_TIMEOUT)"; return false; }
  if (code != 1) {
    char b[96]; snprintf(b, sizeof(b), "DllMain returned %lu (expected 1)", (unsigned long)code);
    err = b; return false;
  }
  return true;
#endif
}
} // namespace vacsafe
