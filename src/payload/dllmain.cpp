#include <windows.h>
#include <cstdio>
#include "stealth.h"
#include "obf.h"
#include "nt_api.h"
#include "game_adapter.h"

// Phase 04: zero plaintext imports for payload-owned calls. Hashes are djb2 of the
// export names (computed offline); plaintext never appears in the binary.
namespace {
using BeepFn = BOOL (WINAPI*)(DWORD, DWORD);
using GetTempPathAFn = DWORD (WINAPI*)(DWORD, LPSTR);
using CreateFileAFn = HANDLE (WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using WriteFileFn = BOOL (WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using CloseHandleFn = BOOL (WINAPI*)(HANDLE);
using DisableTlFn = BOOL (WINAPI*)(HMODULE);
using OdsFn = void (WINAPI*)(LPCSTR);
struct Api {
  BeepFn beep = nullptr;
  GetTempPathAFn getTempPath = nullptr;
  CreateFileAFn createFile = nullptr;
  WriteFileFn writeFile = nullptr;
  CloseHandleFn close = nullptr;
  DisableTlFn disableTl = nullptr;
  OdsFn ods = nullptr;
  bool ok() const { return beep && getTempPath && createFile && writeFile && close && disableTl && ods; }
};
Api g_api;
bool ResolveApi() {
  // djb2: Beep=0x7C82FBA1 GetTempPathA=0x9EF979E9 CreateFileA=0xEB96C5FA
  // WriteFile=0x663CECB0 CloseHandle=0x3870CA07 DisableThreadLibraryCalls=0x530574F5
  // OutputDebugStringA=0x79729F95
  g_api.beep = (BeepFn)vacsafe::nt::GetProcByHash(L"kernel32.dll", 0x7C82FBA1);
  g_api.getTempPath = (GetTempPathAFn)vacsafe::nt::GetProcByHash(L"kernel32.dll", 0x9EF979E9);
  g_api.createFile = (CreateFileAFn)vacsafe::nt::GetProcByHash(L"kernel32.dll", 0xEB96C5FA);
  g_api.writeFile = (WriteFileFn)vacsafe::nt::GetProcByHash(L"kernel32.dll", 0x663CECB0);
  g_api.close = (CloseHandleFn)vacsafe::nt::GetProcByHash(L"kernel32.dll", 0x3870CA07);
  g_api.disableTl = (DisableTlFn)vacsafe::nt::GetProcByHash(L"kernel32.dll", 0x530574F5);
  g_api.ods = (OdsFn)vacsafe::nt::GetProcByHash(L"kernel32.dll", 0x79729F95);
  return g_api.ok();
}
} // namespace

// Phase 03 smoke proof: beep + marker file, then return. Synchronous and short
// (<400ms, inside hijack poll budget). No windows, no focus steal, no threads.
static void SmokeProof() {
  // Raw-entry safe: kernel32 only, no CRT (no snprintf/strlen/printf-family:
  // UCRT per-thread data is never initialized when CRT startup is bypassed).
  // Sensitive literals are compile-time encrypted (stack plaintext only).
  g_api.beep(880, 200);
  VACSAFE_OBF_BUF(rel, "VacSafe-smoke.txt");
  char tmp[MAX_PATH] = {0};
  DWORD n = g_api.getTempPath(sizeof(tmp) - (DWORD)sizeof(rel) - 1, tmp);
  if (!n || n >= sizeof(tmp) - sizeof(rel) - 1) return;
  // append rel (no CRT): manual copy
  char* dst = tmp + n;
  for (size_t i = 0; rel[i]; ++i) *dst++ = rel[i];
  *dst = 0;
  HANDLE f = g_api.createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (f != INVALID_HANDLE_VALUE) {
    VACSAFE_OBF_BUF(body, "VacSafe injected OK\r\n");
    DWORD w = 0;
    g_api.writeFile(f, body, (DWORD)sizeof(body) - 1, &w, nullptr);
    g_api.close(f);
  }
  g_api.ods(VACSAFE_OBF("[VacSafe] payload attached."));
}

// Phase 05: DllMain -> ApplyPost -> hidden init thread -> adapter -> Present hook -> IPC pipe.
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    if (!ResolveApi()) return TRUE; // fail closed: no hashed APIs, no side effects
    g_api.disableTl(hMod);
    vacsafe::stealth::ApplyPost(hMod);
    SmokeProof();
    // TODO: CreateThread(hidden) -> Sdk::Init
  }
  return TRUE;
}
