#include <windows.h>
#include <cstdio>
#include "stealth.h"
#include "game_adapter.h"

// Phase 03 smoke proof: beep + marker file, then return. Synchronous and short
// (<400ms, inside hijack poll budget). No windows, no focus steal, no threads.
static void SmokeProof() {
  // Raw-entry safe: kernel32 only, no CRT (no snprintf/strlen/printf-family:
  // UCRT per-thread data is never initialized when CRT startup is bypassed).
  Beep(880, 200);
  static const char rel[] = "VacSafe-smoke.txt";
  char tmp[MAX_PATH] = {0};
  DWORD n = GetTempPathA(sizeof(tmp) - (DWORD)sizeof(rel) - 1, tmp);
  if (!n || n >= sizeof(tmp) - sizeof(rel) - 1) return;
  // append rel (no CRT): manual copy
  char* dst = tmp + n;
  for (int i = 0; rel[i]; ++i) *dst++ = rel[i];
  *dst = 0;
  HANDLE f = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (f != INVALID_HANDLE_VALUE) {
    static const char body[] = "VacSafe injected OK\r\n";
    DWORD w = 0;
    WriteFile(f, body, (DWORD)sizeof(body) - 1, &w, nullptr);
    CloseHandle(f);
  }
  OutputDebugStringA("[VacSafe] payload attached.");
}

// Phase 05: DllMain -> ApplyPost -> hidden init thread -> adapter -> Present hook -> IPC pipe.
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hMod);
    vacsafe::stealth::ApplyPost(hMod);
    SmokeProof();
    // TODO: CreateThread(hidden) -> Sdk::Init
  }
  return TRUE;
}
