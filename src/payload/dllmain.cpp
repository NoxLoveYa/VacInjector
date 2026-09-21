#include <windows.h>
#include "stealth.h"
#include "game_adapter.h"
// Phase 05: DllMain -> ApplyPost -> hidden init thread -> adapter -> Present hook -> IPC pipe.
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hMod);
    vacsafe::stealth::ApplyPost(hMod);
    OutputDebugStringA("[VacSafe] payload attached (Phase 03 smoke).");
    // TODO: CreateThread(hidden) -> Sdk::Init
  }
  return TRUE;
}
