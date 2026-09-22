#include <windows.h>
#include "stealth.h"
#include "strings.inc"
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
void EspLog(sdk::GameContext* ctx, const Api* api);
void RenderStart(const sdk::IGameAdapter* ad, sdk::GameContext* ctx, const Api* api);
} // namespace vacsafe

namespace vacsafe {
Api g_api;

// Phase 03 smoke proof: beep + marker file, then return. Synchronous and short
// (<400ms, inside hijack poll budget). No windows, no focus steal.
static void SmokeProof() {
  // Raw-entry safe: kernel32 only, no CRT (no snprintf/strlen/printf-family:
  // UCRT per-thread data is never initialized when CRT startup is bypassed).
  // Sensitive strings come from codegen (strings.inc byte arrays); TU holds
  // zero plaintext. NOTE: Beep() deliberately NOT called in-game.
  char rel[32];
  vacsafe::str::CopyTo(vacsafe::str::SID_smoke_rel, rel, sizeof(rel));
  char tmp[MAX_PATH] = {0};
  DWORD n = g_api.getTempPath(sizeof(tmp) - (DWORD)sizeof(rel) - 1, tmp);
  if (!n || n >= sizeof(tmp) - sizeof(rel) - 1) return;
  char* dst = tmp + n;
  for (size_t i = 0; rel[i]; ++i) *dst++ = rel[i];
  *dst = 0;
  HANDLE f = g_api.createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (f != INVALID_HANDLE_VALUE) {
    char body[32];
    vacsafe::str::CopyTo(vacsafe::str::SID_smoke_body, body, sizeof(body));
    DWORD w = 0, len = 0;
    while (body[len]) ++len;
    g_api.writeFile(f, body, len, &w, nullptr);
    g_api.close(f);
  }
  char msg[48];
  vacsafe::str::CopyTo(vacsafe::str::SID_smoke_msg, msg, sizeof(msg));
  g_api.ods(msg);
}

static void InitMark(const char* tag) {
  // InitThread breadcrumb trail (VacSafe-init.txt, separate so adapter stages stay intact).
  __try {
    if (!tag || !tag[0]) return;
    char rel[32];
    vacsafe::str::CopyTo(vacsafe::str::SID_init_rel, rel, sizeof(rel));
    char tmp[MAX_PATH] = {0};
    DWORD n = g_api.getTempPath(sizeof(tmp) - 32, tmp);
    if (!n || n >= sizeof(tmp) - 32) return;
    char* dst = tmp + n;
    for (size_t i = 0; rel[i]; ++i) *dst++ = rel[i];
    *dst = 0;
    HANDLE f = g_api.createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0, len = 0;
    while (tag[len]) ++len;
    g_api.writeFile(f, tag, len, &w, nullptr);
    g_api.close(f);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static DWORD WINAPI InitThread(LPVOID param) {
  InitMark("201-hide-enter");
  (void)param;
  vacsafe::stealth::HideCurrentThreadPub();
  InitMark("202-hide-done");
  vacsafe::sdk::GameContext ctx{};
  g_api.ExeName(ctx.exeName, sizeof(ctx.exeName));
  InitMark("203-exe-done");
  ctx.priv[7] = (uintptr_t)&g_api; // host API cookie for staged file IO
  const vacsafe::sdk::IGameAdapter* ad = vacsafe::CreateAdapterForExe(ctx.exeName);
  InitMark(ad ? "204-adapter-cs2" : "204-adapter-null");
  if (!ad) return 0; // non-game host (busyloop/cmd lab): smoke proof is the deliverable
  bool ok = ad->Init(&ctx); // fills ctx or err; never throws, never CRTs
  InitMark(ok ? "205-init-ok" : "205-init-fail");
  vacsafe::Cs2Proof(&ctx, &g_api);
  InitMark("206-proof-done");
  vacsafe::RenderStart(ad, &ctx, &g_api); // GDI validation pass (no hooks)
  vacsafe::EspLog(&ctx, &g_api); // 60s ESP snapshot loop, then thread exits
  InitMark("207-esp-done");
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
#ifdef VACSAFE_BISECT_S1
    // S1: entry only (no smoke, no thread). Isolates entry/stealth/restore vs smoke/thread.
    return TRUE;
#else
    vacsafe::SmokeProof();
#ifdef VACSAFE_BISECT_S2
    // S2: entry + smoke proof (no thread). Isolates smoke vs init-thread/adapter.
    return TRUE;
#else
    DWORD tid = 0;
    HANDLE h = vacsafe::g_api.createThread(nullptr, 0, vacsafe::InitThread, hMod, 0, &tid);
    if (h) vacsafe::g_api.close(h); // fire-and-forget; thread hides itself + exits
#endif
#endif
  }
  return TRUE;
}
