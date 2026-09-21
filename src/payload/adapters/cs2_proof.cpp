#include "game_adapter.h"
#include "../api.h"
#include "obf.h"
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

bool Cs2Proof(sdk::GameContext* ctx, const Api* api) {
  if (!ctx || !api) return false;
  char out[1024]{};
  size_t p = 0;
  AppendStr(out, sizeof(out), &p, "exe=");
  AppendStr(out, sizeof(out), &p, ctx->exeName);
  AppendStr(out, sizeof(out), &p, "\r\nclient=");
  AppendU64(out, sizeof(out), &p, ctx->mod.clientBase);
  AppendStr(out, sizeof(out), &p, "\r\nentityList=");
  AppendU64(out, sizeof(out), &p, ctx->entityList);
  AppendStr(out, sizeof(out), &p, "\r\nlocalPlayer=");
  AppendU64(out, sizeof(out), &p, ctx->localPlayer);
  AppendStr(out, sizeof(out), &p, "\r\nviewMatrix=");
  AppendU64(out, sizeof(out), &p, ctx->viewMatrix);
  AppendStr(out, sizeof(out), &p, "\r\nschema=");
  AppendU32(out, sizeof(out), &p, (uint32_t)ctx->priv[4]);
  AppendStr(out, sizeof(out), &p, " healthOff=");
  AppendU64(out, sizeof(out), &p, ctx->priv[0]);
  AppendStr(out, sizeof(out), &p, " teamOff=");
  AppendU64(out, sizeof(out), &p, ctx->priv[1]);

  sdk::Player players[16]{};
  int n = kCs2Adapter.GetPlayers(ctx, players, 16);
  AppendStr(out, sizeof(out), &p, "\r\nentities=");
  AppendU32(out, sizeof(out), &p, (uint32_t)(n < 0 ? 0 : n));
  if (n > 0) {
    AppendStr(out, sizeof(out), &p, " p0hp=");
    AppendU32(out, sizeof(out), &p, (uint32_t)(players[0].health < 0 ? 0 : players[0].health));
    AppendStr(out, sizeof(out), &p, " p0team=");
    AppendU32(out, sizeof(out), &p, (uint32_t)(players[0].team < 0 ? 0 : players[0].team));
  }
  if (ctx->err[0]) {
    AppendStr(out, sizeof(out), &p, "\r\nnote=");
    AppendStr(out, sizeof(out), &p, ctx->err);
  }
  AppendStr(out, sizeof(out), &p, "\r\nbid=");
  AppendStr(out, sizeof(out), &p, VACSAFE_PBID);
  AppendStr(out, sizeof(out), &p, "\r\n");
  out[sizeof(out) - 1] = 0;

  VACSAFE_OBF_BUF(rel, "VacSafe-cs2.txt");
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
  return w != 0;
}

} // namespace vacsafe
