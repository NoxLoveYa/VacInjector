#include "injector_core.h"
#include <windows.h>
#include <tlhelp32.h>
#include <cstring>

namespace vacsafe {
// APC fallback for threads that rarely get hijacked cleanly (GMod Lua worker threads).
// Allocate tiny RX stub calling DllMain(hMod,1,0) then setting a flag byte. Freed right after.
#if defined(_WIN64)
static const uint8_t kStub64[] = {
  0x48, 0xB9, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov rcx, hMod (patched)
  0xBA, 0x01,0x00,0x00,0x00,                           // mov edx, 1
  0x4D, 0x31, 0xC0,                                     // xor r8, r8
  0x48, 0xB8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov rax, DllMain (patched)
  0xFF, 0xD0,                                           // call rax
  0xC6, 0x05, 0x00,0x00,0x00,0x00, 0x01,                // mov byte [rel flag],1 (patched disp)
  0xC3                                                  // ret
};
#endif

bool ExecViaApc(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err) {
#if !defined(_WIN64)
  err = "APC x86 path needs x86 helper (E_ARCH_MISMATCH)";
  return false;
#else
  if (!hProc || !entry) { err = "bad args"; return false; }
  BOOL wow = FALSE; IsWow64Process(hProc, &wow);
  if (wow) { err = "x64->x86 APC needs x86 helper (E_ARCH_MISMATCH)"; return false; }

  SIZE_T stubSize = sizeof(kStub64) + 16;
  void* remote = VirtualAllocEx(hProc, nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { err = "APC alloc failed"; return false; }
  uint8_t local[128]{}; memcpy(local, kStub64, sizeof(kStub64));
  uintptr_t hMod = (uintptr_t)arg, fn = (uintptr_t)entry;
  memcpy(local + 2, &hMod, 8);
  memcpy(local + 20, &fn, 8);
  uintptr_t stubAddr = (uintptr_t)remote;
  uintptr_t flagAddr = stubAddr + sizeof(kStub64);
  int32_t disp = (int32_t)(flagAddr - (stubAddr + 30 + 7));
  memcpy(local + 30 + 2, &disp, 4);

  SIZE_T w = 0;
  uint8_t zero = 0;
  if (!WriteProcessMemory(hProc, remote, local, sizeof(kStub64), &w) ||
      !WriteProcessMemory(hProc, (LPVOID)flagAddr, &zero, 1, &w)) {
    err = "APC write failed"; VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); return false;
  }
  DWORD old = 0; VirtualProtectEx(hProc, remote, sizeof(kStub64), PAGE_EXECUTE_READ, &old);

  DWORD pid = GetProcessId(hProc);
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  int queued = 0;
  if (snap != INVALID_HANDLE_VALUE) {
    THREADENTRY32 te{ sizeof(te) };
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
      if (te.th32OwnerProcessID != pid) continue;
      HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
      if (!th) continue;
      if (QueueUserAPC((PAPCFUNC)remote, th, 0) != 0) ++queued;
      CloseHandle(th);
    }
    CloseHandle(snap);
  }
  if (!queued) { err = "APC: no threads queued"; VirtualFreeEx(hProc, remote, 0, MEM_RELEASE); return false; }

  DWORD waited = 0;
  while (waited < timeoutMs) {
    Sleep(50); waited += 50;
    uint8_t f = 0; SIZE_T r = 0;
    if (ReadProcessMemory(hProc, (LPCVOID)flagAddr, &f, 1, &r) && f == 1) {
      VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
      return true;
    }
  }
  VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
  err = "APC timeout (threads never went alertable; use Hijack for this game)";
  return false;
#endif
}
} // namespace vacsafe
