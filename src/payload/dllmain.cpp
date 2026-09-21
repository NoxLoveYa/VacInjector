#include <windows.h>
#include "stealth.h"
#include "obf.h"
#include "api.h"
#include "game_adapter.h"

// Payload-owned forward decls (defined in adapter_factory.cpp / cs2_adapter.cpp).
// CRT-free: all payload TUs obey the raw-entry law (kernel32 only, no CRT calls).
namespace vacsafe {
namespace sdk {
struct IGameAdapter;
struct GameContext;
}
struct Api;
const sdk::IGameAdapter* CreateAdapterForExe(const char* exeName);
bool Cs2Proof(sdk::GameContext* ctx, const Api* api);
} // namespace vacsafe

namespace vacsafe {
Api g_api;

// Phase 03 smoke proof: beep + marker file, then return. Synchronous and short
// (<400ms, inside hijack poll budget). No windows, no focus steal.
static void SmokeProof() {
  // Raw-entry safe: kernel32 only, no CRT (no snprintf/strlen/printf-family:
  // UCRT per-thread data is never initialized when CRT startup is bypassed).
  // Sensitive literals are compile-time encrypted (stack plaintext only).
  // NOTE: Beep() deliberately NOT called in-game: on exclusive-audio targets it
  // re-enters the audio stack from a hijacked thread (suspect in CS2 fastfails).
  // Audible proof returns via loader-side beep instead (see VacSafe.cpp TODO).
  VACSAFE_OBF_BUF(rel, "VacSafe-smoke.txt");
  char tmp[MAX_PATH] = {0};
  DWORD n = g_api.getTempPath(sizeof(tmp) - (DWORD)sizeof(rel) - 1, tmp);
  if (!n || n >= sizeof(tmp) - sizeof(rel) - 1) return;
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

static DWORD WINAPI InitThread(LPVOID param) {
  (void)param;
  vacsafe::stealth::HideCurrentThreadPub();
  vacsafe::sdk::GameContext ctx{};
  g_api.ExeName(ctx.exeName, sizeof(ctx.exeName));
  ctx.priv[7] = (uintptr_t)&g_api; // host API cookie for staged file IO
  const vacsafe::sdk::IGameAdapter* ad = vacsafe::CreateAdapterForExe(ctx.exeName);
  if (!ad) return 0; // non-game host (busyloop/cmd lab): smoke proof is the deliverable
  ad->Init(&ctx);    // fills ctx or err; never throws, never CRTs
  vacsafe::Cs2Proof(&ctx, &g_api);
  return 0;
}

} // namespace vacsafe

// NOTE: DllMain stays at GLOBAL scope with __stdcall decoration (_DllMain@12) so the
// linker MAP lookup ("DllMain@12") keeps resolving the raw entry. Do not namespace it.
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    if (!vacsafe::g_api.Resolve()) return TRUE; // fail closed
    vacsafe::g_api.disableTl(hMod);
    vacsafe::stealth::ApplyPost(hMod);
    vacsafe::SmokeProof();
    DWORD tid = 0;
    HANDLE h = vacsafe::g_api.createThread(nullptr, 0, vacsafe::InitThread, hMod, 0, &tid);
    if (h) vacsafe::g_api.close(h); // fire-and-forget; thread hides itself + exits
  }
  return TRUE;
}
