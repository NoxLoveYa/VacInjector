#include "game_adapter.h"
#include "../api.h"
#include "strings.inc"
#if __has_include("build_id.h")
#include "build_id.h"
#endif
#ifdef VACSAFE_BUILD_ID
#define VACSAFE_PBID VACSAFE_BUILD_ID
#else
#define VACSAFE_PBID "nobid"
#endif

// CS2 proof read: modules + globals + schema status + entity count + local HP.
// Writes %TEMP%\VacSafe-cs2.txt with manual formatting (no CRT). CRT-free.
namespace vacsafe {

extern const sdk::IGameAdapter kCs2Adapter;

static void AppendStr(char* dst, size_t cap, size_t* pos, const char* s) {
  if (!dst || !pos || !s) return;
  for (size_t i = 0; s[i] && *pos + 1 < cap; ++i) dst[(*pos)++] = s[i];
}
static void AppendU64(char* dst, size_t cap, size_t* pos, uint64_t v) {
  char tmp[20];
  sdk::U64ToHex(tmp, sizeof(tmp), v);
  AppendStr(dst, cap, pos, tmp);
}
static void AppendU32(char* dst, size_t cap, size_t* pos, uint32_t v) {
  char tmp[14];
  sdk::U32ToDec(tmp, sizeof(tmp), v);
  AppendStr(dst, cap, pos, tmp);
}

static void AppendId(char* dst, size_t cap, size_t* pos, unsigned id) {
  char tmp[48];
  vacsafe::str::CopyTo(id, tmp, sizeof(tmp));
  AppendStr(dst, cap, pos, tmp);
}

bool Cs2Proof(sdk::GameContext* ctx, const Api* api) {
  if (!ctx || !api) return false;
  // Reuse stage file for proof milestones (300+).
  auto mark = [&](uint32_t s) {
    __try {
      char rel[32];
      vacsafe::str::CopyTo(vacsafe::str::SID_init_rel, rel, sizeof(rel));
      char tmp[MAX_PATH] = {0};
      DWORD tn = api->getTempPath(sizeof(tmp) - 32, tmp);
      if (!tn || tn >= sizeof(tmp) - 32) return;
      char* dst = tmp + tn;
      for (size_t i = 0; rel[i]; ++i) *dst++ = rel[i];
      *dst = 0;
      char ob[64]{};
      size_t q = 0;
      const char* pre = "proof=";
      while (*pre && q + 1 < sizeof(ob)) ob[q++] = *pre++;
      char nb[12]; int nn = 0;
      uint32_t v = s;
      if (!v) nb[nn++] = '0';
      while (v && nn < 11) { nb[nn++] = (char)('0' + v % 10); v /= 10; }
      while (nn > 0 && q + 1 < sizeof(ob)) ob[q++] = nb[--nn];
      ob[q++] = '\r'; ob[q++] = '\n'; ob[q] = 0;
      HANDLE f = api->createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (f == INVALID_HANDLE_VALUE) return;
      DWORD w = 0;
      api->writeFile(f, ob, (DWORD)q, &w, nullptr);
      api->close(f);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
  };
  mark(301);
  char out[1024]{};
  size_t p = 0;
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_exe);
  AppendStr(out, sizeof(out), &p, ctx->exeName);
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_client);
  AppendU64(out, sizeof(out), &p, ctx->mod.clientBase);
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_ent);
  AppendU64(out, sizeof(out), &p, ctx->entityList);
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_lp);
  AppendU64(out, sizeof(out), &p, ctx->localPlayer);
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_vm);
  AppendU64(out, sizeof(out), &p, ctx->viewMatrix);
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_schema);
  AppendU32(out, sizeof(out), &p, (uint32_t)ctx->priv[4]);
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_hoff);
  AppendU64(out, sizeof(out), &p, ctx->priv[0]);
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_toff);
  AppendU64(out, sizeof(out), &p, ctx->priv[1]);

  sdk::Player players[16]{};
  int n = kCs2Adapter.GetPlayers(ctx, players, 16);
  mark(302);
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_ents);
  AppendU32(out, sizeof(out), &p, (uint32_t)(n < 0 ? 0 : n));
  if (n > 0) {
    AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_hp);
    AppendU32(out, sizeof(out), &p, (uint32_t)(players[0].health < 0 ? 0 : players[0].health));
    AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_team);
    AppendU32(out, sizeof(out), &p, (uint32_t)(players[0].team < 0 ? 0 : players[0].team));
  }
  if (ctx->err[0]) {
    AppendId(out, sizeof(out), &p, vacsafe::str::SID_d_note);
    AppendStr(out, sizeof(out), &p, ctx->err);
  }
  AppendId(out, sizeof(out), &p, vacsafe::str::SID_p_bid);
  AppendStr(out, sizeof(out), &p, VACSAFE_PBID);
  AppendStr(out, sizeof(out), &p, "\r\n");
  out[sizeof(out) - 1] = 0;

  char rel[32];
  vacsafe::str::CopyTo(vacsafe::str::SID_proof_rel, rel, sizeof(rel));
  char tmp[MAX_PATH] = {0};
  DWORD tn = api->getTempPath(sizeof(tmp) - (DWORD)sizeof(rel) - 1, tmp);
  if (!tn || tn >= sizeof(tmp) - sizeof(rel) - 1) return false;
  char* dst = tmp + tn;
  for (size_t i = 0; rel[i]; ++i) *dst++ = rel[i];
  *dst = 0;
  HANDLE f = api->createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (f == INVALID_HANDLE_VALUE) return false;
  DWORD w = 0;
  size_t len = 0;
  while (len < sizeof(out) && out[len]) ++len;
  api->writeFile(f, out, (DWORD)len, &w, nullptr);
  api->close(f);
  mark(303);
  return w != 0;
}

} // namespace vacsafe
