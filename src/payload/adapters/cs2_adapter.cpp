#include "game_adapter.h"
#include "nt_api.h"
#include "peb.h"
#include "strings.inc"
#include "../api.h"
#include <windows.h>
#include <winternl.h>
#include <cstddef>

// Stack-decrypt a string ID for immediate call-arg use (never stored).
#define STRBUF(name, sid) char name[64]; vacsafe::str::CopyTo(vacsafe::str::sid, name, sizeof(name))
#include <windows.h>
#include <winternl.h>
#include <cstddef>

// CS2 (Source 2, x64) adapter — Phase 05 v1.
// Globals via pattern scan (guarded, stale-sig safe). Field offsets via live
// Schema walk (FindTypeScopeForModule idx 13 / FindDeclaredClass idx 2,
// class {name@0x8, fieldCount@0x24, fields@0x30}, field {name@0, off@0x10}).
// Everything SEH-guarded + vtable targets range-checked against loaded modules:
// stale indices fail closed with ctx->err, never wild-call.
// Staged breadcrumbs rewrite VacSafe-cs2.txt at every milestone so a crash
// leaves the exact stage + error behind.
// CRT-free: kernel32 only, manual loops, no heap.
namespace vacsafe {
namespace {

// Screen size cache (POD statics: zero-init, assigned in Init; raw-safe).
static int sScrW = 0;
static int sScrH = 0;

static const vacsafe::Api* CtxApi(sdk::GameContext* ctx) {
  if (!ctx) return nullptr;
  return (const vacsafe::Api*)(uintptr_t)ctx->priv[7];
}

// Minimal stage writer: "stage=N exe=X [a=0x.. b=0x..] err=Y". Overwrites proof file.
// Append helpers: decrypted-ID text + hex, no literals, no CRT.
static void AppId(char* dst, size_t cap, size_t* pos, unsigned id) {
  char tmp[80];
  vacsafe::str::CopyTo(id, tmp, sizeof(tmp));
  for (size_t i = 0; tmp[i] && *pos + 1 < cap; ++i) dst[(*pos)++] = tmp[i];
}
static void AppHex(char* dst, size_t cap, size_t* pos, uint64_t v, bool skip0x) {
  char hx[20];
  sdk::U64ToHex(hx, sizeof(hx), v);
  for (size_t i = skip0x ? 2 : 0; hx[i] && *pos + 1 < cap; ++i) dst[(*pos)++] = hx[i];
}
static void AppStr(char* dst, size_t cap, size_t* pos, const char* s) {
  if (!s) return;
  for (size_t i = 0; s[i] && *pos + 1 < cap; ++i) dst[(*pos)++] = s[i];
}
static void SetErrId(sdk::GameContext* ctx, unsigned id) {
  char tmp[96];
  vacsafe::str::CopyTo(id, tmp, sizeof(tmp));
  sdk::SetErr(ctx, tmp);
}

static void StageDetail(sdk::GameContext* ctx, uint32_t n, uint64_t a, uint64_t b) {
  if (!ctx) return;
  ctx->priv[5] = n;
  __try {
    const vacsafe::Api* api = CtxApi(ctx);
    if (!api || !api->createFile || !api->getTempPath) return;
    char rel[32];
    vacsafe::str::CopyTo(vacsafe::str::SID_proof_rel, rel, sizeof(rel));
    char tmp[MAX_PATH] = {0};
    DWORD tn = api->getTempPath(sizeof(tmp) - (DWORD)sizeof(rel) - 1, tmp);
    if (!tn || tn >= sizeof(tmp) - sizeof(rel) - 1) return;
    char* dst = tmp + tn;
    for (size_t i = 0; rel[i]; ++i) *dst++ = rel[i];
    *dst = 0;
    char out[256]{};
    size_t p = 0;
    AppId(out, sizeof(out), &p, vacsafe::str::SID_d_stage);
    char nb[12]; int nn = 0;
    uint32_t v = n;
    if (!v) nb[nn++] = '0';
    while (v && nn < 11) { nb[nn++] = (char)('0' + v % 10); v /= 10; }
    while (nn > 0 && p + 1 < sizeof(out)) out[p++] = nb[--nn];
    AppId(out, sizeof(out), &p, vacsafe::str::SID_d_exe);
    for (size_t i = 0; ctx->exeName[i] && p + 1 < sizeof(out); ++i) out[p++] = ctx->exeName[i];
    if (a || b) {
      AppId(out, sizeof(out), &p, vacsafe::str::SID_d_a);
      AppHex(out, sizeof(out), &p, a, false);
      AppId(out, sizeof(out), &p, vacsafe::str::SID_d_b);
      AppHex(out, sizeof(out), &p, b, false);
    }
    if (ctx->err[0]) {
      AppId(out, sizeof(out), &p, vacsafe::str::SID_d_err);
      for (size_t i = 0; ctx->err[i] && p + 1 < sizeof(out); ++i) out[p++] = ctx->err[i];
    }
    if (p + 2 < sizeof(out)) { out[p++] = '\r'; out[p++] = '\n'; }
    out[p] = 0;
    HANDLE f = api->createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    api->writeFile(f, out, (DWORD)p, &w, nullptr);
    api->close(f);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void Stage(sdk::GameContext* ctx, uint32_t n) {
  StageDetail(ctx, n, 0, 0);
}

// --- signatures (a2x/cs2-dumper lineage, maintained; guarded at runtime) ---
// dwEntityList: store-form anchor (old load-form still matches dead code post-update).
static const uint8_t kEntPat[] = {0x48,0x89,0x0D,0,0,0,0, 0xE9,0,0,0,0, 0xCC};
static const char kEntMask[] = "xxx????x????x";
static const uint8_t kLpPat[] = {0x48,0x8D,0x05,0,0,0,0, 0xC3,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC, 0x48,0x83,0xEC,0, 0x8B,0x0D};
static const char kLpMask[] = "xxx????xxxxxxxxxxxx?xx";
static const uint8_t kVmPat[] = {0x48,0x8D,0x0D,0,0,0,0, 0x48,0xC1,0xE0,0x06};
static const char kVmMask[] = "xxx????xxx";

static bool ScanGlobal(sdk::GameContext* ctx, const uint8_t* pat, const char* mask, size_t len,
                       unsigned whatId, uintptr_t* out) {
  uintptr_t m = sdk::PatternScan(ctx->mod.clientBase, ctx->mod.clientSize, pat, mask, len);
  if (!m) {
    // Include module bounds: distinguishes wrong-base/size from true sig drift.
    char eb[sdk::kMaxErrLen];
    size_t i = 0;
    AppId(eb, sizeof(eb), &i, vacsafe::str::SID_d_sigstale);
    // whatId names the global (decrypted temp, never stored)
    {
      char wn[32];
      vacsafe::str::CopyTo(whatId, wn, sizeof(wn));
      AppStr(eb, sizeof(eb), &i, wn);
    }
    AppId(eb, sizeof(eb), &i, vacsafe::str::SID_d_base);
    AppHex(eb, sizeof(eb), &i, ctx->mod.clientBase, false);
    AppId(eb, sizeof(eb), &i, vacsafe::str::SID_d_size);
    AppHex(eb, sizeof(eb), &i, ctx->mod.clientSize, false);
    // map forensics survive into the miss line (stage file overwrites per stage)
    AppId(eb, sizeof(eb), &i, vacsafe::str::SID_d_mz);
    AppHex(eb, sizeof(eb), &i, ctx->priv[8], true);
    AppId(eb, sizeof(eb), &i, vacsafe::str::SID_d_t);
    AppHex(eb, sizeof(eb), &i, ctx->priv[9], true);
    AppId(eb, sizeof(eb), &i, vacsafe::str::SID_d_ninst);
    AppHex(eb, sizeof(eb), &i, ctx->priv[6], true);
    AppId(eb, sizeof(eb), &i, vacsafe::str::SID_d_pm);
    AppHex(eb, sizeof(eb), &i, ctx->priv[11], true);
    eb[i] = 0;
    sdk::SetErr(ctx, eb);
    return false;
  }
  *out = sdk::ResolveRip(m, 7, 3);
  return *out != 0;
}

// --- schema vtable helpers (Binja-verified on schemasystem.dll 2026-09-21) ---
// CSchemaSystem table: [11]=GlobalTypeScope [12]=FindOrCreate [13]=FindTypeScopeForModule.
// CSchemaSystemTypeScope table: [2]=FindDeclaredClass.
// TRUE signatures (decompiled): System[13](this, name, outOrNull)->scope;
// Scope[2](this, out**, name)->void. Calling with fewer args faults or returns
// garbage (2-arg System[13] writes through garbage r8; 2-arg Scope[2] misreads rax).
typedef void* (*FindScopeFn)(void*, const char*, void*);
typedef void (*FindClassFn)(void*, void**, const char*);

static uintptr_t VFunc(void* obj, size_t idx) {
  __try {
    if (!obj) return 0;
    uintptr_t vt = sdk::Read<uintptr_t>((uintptr_t)obj);
    if (!vt) return 0;
    return sdk::Read<uintptr_t>(vt + idx * 8);
  } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static void* CallScope(sdk::GameContext* ctx, void* sys, const char* mod) {
  __try {
    FindScopeFn f = (FindScopeFn)VFunc(sys, 13);
    if (!f) return nullptr;
    if (!nt::AddressInModules((uintptr_t)f)) {
      SetErrId(ctx, vacsafe::str::SID_e_vt13);
      return nullptr;
    }
    return f(sys, mod, nullptr); // out=nullptr: guarded writes skipped by callee
  } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static void* CallClass(sdk::GameContext* ctx, void* scope, const char* cls) {
  __try {
    FindClassFn f = (FindClassFn)VFunc(scope, 2);
    if (!f) return nullptr;
    if (!nt::AddressInModules((uintptr_t)f)) {
      SetErrId(ctx, vacsafe::str::SID_e_vt2);
      return nullptr;
    }
    void* out = nullptr;
    f(scope, &out, cls);
    return out;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static bool NameIs(const char* a, const char* b) {
  if (!a || !b) return false;
  for (int i = 0; i < 64; ++i) {
    if (a[i] != b[i]) return false;
    if (!a[i]) return true;
  }
  return false;
}

// Walk class + base chain (cap 8) for field; returns full offset or -1.
static int FindField(void* cls, const char* field) {
  __try {
    uintptr_t cur = (uintptr_t)cls;
    intptr_t acc = 0;
    for (int depth = 0; depth < 8 && cur; ++depth) {
      int16_t count = sdk::Read<int16_t>(cur + 0x24);
      uintptr_t fields = sdk::Read<uintptr_t>(cur + 0x30);
      if (count > 0 && count < 768 && fields) {
        for (int i = 0; i < count; ++i) {
          uintptr_t f = fields + (uintptr_t)i * 0x20;
          uintptr_t nm = sdk::Read<uintptr_t>(f);
          if (!nm) continue;
          char nb[64]{};
          if (!sdk::ReadBuf(nm, nb, sizeof(nb) - 1)) continue;
          if (NameIs(nb, field)) {
            int16_t off = sdk::Read<int16_t>(f + 0x10);
            intptr_t full = acc + off;
            if (full < 0 || full > 0x10000) return -1;
            return (int)full;
          }
        }
      }
      // first base class: parent@0x38 -> {off@0, class@8}
      uintptr_t pb = sdk::Read<uintptr_t>(cur + 0x38);
      if (!pb) break;
      int32_t boff = sdk::Read<int32_t>(pb);
      uintptr_t ncls = sdk::Read<uintptr_t>(pb + 8);
      if (!ncls || ncls == cur) break;
      if (boff < 0 || boff > 0x10000) break;
      acc += boff;
      cur = ncls;
    }
    return -1;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}

struct SchemaOut {
  int offHealth = -1, offTeam = -1, offScene = -1, offOrigin = -1;
  bool ok = false;
};

static bool ResolveSchema(sdk::GameContext* ctx, SchemaOut* so) {
  if (!ctx->mod.schemaBase) { SetErrId(ctx, vacsafe::str::SID_e_noschema); return false; }
  Stage(ctx, 60);
  // Range-gate CreateInterface too: must live inside schemasystem.dll.
  STRBUF(nm_ci, SID_api_createinterface);
  void* ci = nt::GetProcByName((void*)ctx->mod.schemaBase, nm_ci);
  if (!ci || !nt::AddressInModules((uintptr_t)ci)) { SetErrId(ctx, vacsafe::str::SID_e_noci); return false; }
  typedef void* (*CiFn)(const char*, int*);
  void* sys = nullptr;
  STRBUF(nm_ss, SID_api_schemasys);
  __try { sys = ((CiFn)ci)(nm_ss, nullptr); }
  __except (EXCEPTION_EXECUTE_HANDLER) { sys = nullptr; }
  if (!sys) { SetErrId(ctx, vacsafe::str::SID_e_nosys); return false; }
  Stage(ctx, 65);
  STRBUF(nm_mod, SID_mod_client);
  void* scope = CallScope(ctx, sys, nm_mod);
  if (!scope) { if (!ctx->err[0]) SetErrId(ctx, vacsafe::str::SID_e_noscope); Stage(ctx, 69); return false; }
  Stage(ctx, 70);
  STRBUF(nm_pawn, SID_cls_pawn);
  void* pawn = CallClass(ctx, scope, nm_pawn);
  if (!pawn) { if (!ctx->err[0]) SetErrId(ctx, vacsafe::str::SID_e_nopawn); Stage(ctx, 79); return false; }
  Stage(ctx, 80);
  STRBUF(nm_hp, SID_fld_health);
  STRBUF(nm_team, SID_fld_team);
  STRBUF(nm_sn, SID_fld_scene);
  so->offHealth = FindField(pawn, nm_hp);
  so->offTeam = FindField(pawn, nm_team);
  so->offScene = FindField(pawn, nm_sn);
  STRBUF(nm_node, SID_cls_node);
  void* node = CallClass(ctx, scope, nm_node);
  STRBUF(nm_org, SID_fld_origin);
  if (node) so->offOrigin = FindField(node, nm_org);
  so->ok = (so->offHealth >= 0 && so->offTeam >= 0);
  Stage(ctx, 90);
  return true;
}

// --- entity list walk lives in Cs2Players below (single implementation) ---

static const char* Cs2Name() {
  static char buf[16] = {0};
  if (!buf[0]) vacsafe::str::CopyTo(vacsafe::str::SID_n_cs2, buf, sizeof(buf));
  return buf;
}

// Offsets file override (%TEMP%\VacSafe-offsets.ini, written by the loader from
// offsets/cs2.json): lines "name=RVAhex". Nonzero entries win over pattern scans,
// so game updates need a JSON edit, not a rebuild. CRT-free manual parse.
static uint32_t ParseHex(const char* s, size_t n) {
  uint32_t v = 0;
  for (size_t i = 0; i < n; ++i) {
    char c = s[i];
    uint32_t d = 0;
    if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
    else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
    else break;
    v = (v << 4) | d;
  }
  return v;
}

static void LoadOffsetsIni(sdk::GameContext* ctx) {
  __try {
    const vacsafe::Api* api = CtxApi(ctx);
    if (!api || !api->createFile || !api->readFile || !api->getFileSize) return;
    char rel[32];
    vacsafe::str::CopyTo(vacsafe::str::SID_offsets_rel, rel, sizeof(rel));
    char tmp[MAX_PATH] = {0};
    DWORD tn = api->getTempPath(sizeof(tmp) - 32, tmp);
    if (!tn || tn >= sizeof(tmp) - 32) return;
    char* dst = tmp + tn;
    for (size_t i = 0; rel[i]; ++i) *dst++ = rel[i];
    *dst = 0;
    HANDLE f = api->createFile(tmp, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD hi = 0;
    DWORD sz = api->getFileSize(f, &hi);
    if (!sz || hi || sz > 512) { api->close(f); return; }
    char buf[512]{};
    DWORD rd = 0;
    if (!api->readFile(f, buf, sz, &rd, nullptr) || rd != sz) { api->close(f); return; }
    api->close(f);
    size_t i = 0;
    while (i < rd) {
      size_t ls = i;
      while (ls < rd && buf[ls] != '\n' && buf[ls] != '\r') ++ls;
      size_t eq = i;
      while (eq < ls && buf[eq] != '=') ++eq;
      if (eq < ls && ctx->mod.clientBase) {
        uint32_t v = ParseHex(buf + eq + 1, ls - eq - 1);
        if (v) {
          if (buf[i] == 'e') ctx->entityList = ctx->mod.clientBase + v;
          else if (buf[i] == 'l') ctx->localPlayer = ctx->mod.clientBase + v;
          else if (buf[i] == 'v') ctx->viewMatrix = ctx->mod.clientBase + v;
        }
      }
      i = ls + 1;
      while (i < rd && (buf[i] == '\n' || buf[i] == '\r')) ++i;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Mapping sanity: MZ at base? first .text qword? how many client.dll instances?
// Distinguishes wrong-base vs runtime-patched-content vs scanner bug.
static void MapSanity(sdk::GameContext* ctx) {
  __try {
    uint8_t mz[2] = {0};
    uint8_t t0[8] = {0};
    bool okMz = sdk::ReadBuf(ctx->mod.clientBase, mz, 2);
    bool okT = sdk::ReadBuf(ctx->mod.clientBase + 0x1000, t0, 8);
    // count InMemoryOrder entries named client.dll
    int count = 0;
    {
      PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
      if (peb && peb->Ldr) {
        auto* ldr = (vacsafe::peb::LdrData*)peb->Ldr;
        LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
        for (LIST_ENTRY* cur = head->Flink; cur != head && count < 9; cur = cur->Flink) {
          auto* e = (vacsafe::peb::LdrEntry*)((uint8_t*)cur - offsetof(vacsafe::peb::LdrEntry, InMemoryOrderLinks));
          const wchar_t* b = e->BaseDllName.Buffer;
          if (!b) continue;
          // exact "client.dll" case-insensitive (10 chars + NUL)
          const wchar_t want[] = L"client.dll";
          int i = 0;
          for (; i < 10; ++i) {
            wchar_t ca = b[i], cb = want[i];
            if (ca >= L'A' && ca <= L'Z') ca += 32;
            if (ca != cb) break;
          }
          if (i == 10 && b[10] == 0) ++count;
        }
      }
    }
    // pack: mz bytes + text qword lo32 + count into priv + extend err line
    ctx->priv[6] = (uintptr_t)count;
    uint16_t mzw = (okMz) ? (uint16_t)(mz[0] | ((uint16_t)mz[1] << 8)) : 0;
    ctx->priv[8] = mzw;
    uint32_t tlo = 0, thi = 0;
    if (okT) {
      tlo = (uint32_t)t0[0] | ((uint32_t)t0[1] << 8) | ((uint32_t)t0[2] << 16) | ((uint32_t)t0[3] << 24);
      thi = (uint32_t)t0[4] | ((uint32_t)t0[5] << 8) | ((uint32_t)t0[6] << 16) | ((uint32_t)t0[7] << 24);
    }
    ctx->priv[9] = tlo;
    ctx->priv[10] = thi;
    char eb[96]{};
    size_t p = 0;
    AppId(eb, sizeof(eb), &p, vacsafe::str::SID_d_map);
    if (okMz) {
      const char* dig = "0123456789ABCDEF";
      eb[p++] = dig[(mz[0] >> 4) & 0xF]; eb[p++] = dig[mz[0] & 0xF];
      eb[p++] = dig[(mz[1] >> 4) & 0xF]; eb[p++] = dig[mz[1] & 0xF];
    } else { eb[p++] = '?'; eb[p++] = '?'; }
    AppId(eb, sizeof(eb), &p, vacsafe::str::SID_d_t);
    if (okT) {
      const char* dig = "0123456789ABCDEF";
      for (int i = 0; i < 8 && p + 2 < sizeof(eb); ++i) {
        eb[p++] = dig[(t0[i] >> 4) & 0xF]; eb[p++] = dig[t0[i] & 0xF];
      }
    } else {
      char un[16];
      vacsafe::str::CopyTo(vacsafe::str::SID_d_unreadable, un, sizeof(un));
      AppStr(eb, sizeof(eb), &p, un);
    }
    AppId(eb, sizeof(eb), &p, vacsafe::str::SID_d_ninst);
    eb[p++] = (char)('0' + (count > 9 ? 9 : count));
    // DIAG (temporary): compare 16B at file-verified RVA 0x9AA44A against the
    // expected file bytes. Verdict in priv[11]: 0xFF match, 0xFE fault, else
    // first mismatch index. Settles wrong-base vs runtime-patch vs scanner-bug.
    {
      static const uint8_t kExp[16] = {
        0x48,0x8B,0x0D,0xEF,0x57,0x89,0x01,0x48,
        0x89,0x7C,0x24,0x30,0x8B,0xFA,0xC1,0xEB };
      uint8_t probe[16] = {0};
      uintptr_t verdict = 0xFE;
      if (sdk::ReadBuf(ctx->mod.clientBase + 0x9AA44A, probe, 16)) {
        verdict = 0xFF;
        for (int i = 0; i < 16; ++i) {
          if (probe[i] != kExp[i]) { verdict = (uintptr_t)i; break; }
        }
      }
      ctx->priv[11] = verdict;
    }
    eb[p] = 0;
    sdk::SetErr(ctx, eb);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static bool Cs2Init(sdk::GameContext* ctx) {
  Stage(ctx, 10);
  if (!sdk::FillModules(ctx)) { Stage(ctx, 19); return false; }
  MapSanity(ctx); // sets err with map/mz/text/instances; ScanGlobal overwrites on miss
  StageDetail(ctx, 20, ctx->mod.clientBase, ctx->mod.clientSize);
  LoadOffsetsIni(ctx); // ini RVAs win; missing entries fall through to scans
  if (!ctx->entityList) {
    if (!ScanGlobal(ctx, kEntPat, kEntMask, sizeof(kEntPat), vacsafe::str::SID_w_ent, &ctx->entityList)) { Stage(ctx, 29); return false; }
  }
  Stage(ctx, 30);
  if (!ctx->localPlayer) {
    if (!ScanGlobal(ctx, kLpPat, kLpMask, sizeof(kLpPat), vacsafe::str::SID_w_lp, &ctx->localPlayer)) { Stage(ctx, 39); return false; }
  }
  Stage(ctx, 40);
  if (!ctx->viewMatrix) {
    if (!ScanGlobal(ctx, kVmPat, kVmMask, sizeof(kVmPat), vacsafe::str::SID_w_vm, &ctx->viewMatrix)) { Stage(ctx, 49); return false; }
  }
  Stage(ctx, 50);
  SchemaOut so{};
  if (ResolveSchema(ctx, &so)) {
    ctx->priv[0] = (uintptr_t)(intptr_t)so.offHealth;
    ctx->priv[1] = (uintptr_t)(intptr_t)so.offTeam;
    ctx->priv[2] = (uintptr_t)(intptr_t)so.offScene;
    ctx->priv[3] = (uintptr_t)(intptr_t)so.offOrigin;
    ctx->priv[4] = so.ok ? 1 : 0;
  } else {
    ctx->priv[4] = 0; // schema failed: err already set; globals still valid
    Stage(ctx, 95);
  }
  // Screen size for W2S (SM_CXSCREEN=0/SM_CYSCREEN=1 numeric; hashed API).
  // user32 may be absent on console hosts: fall back to 1920x1080 (validation
  // only; GUI games always map user32 so production W2S stays exact).
  {
    const vacsafe::Api* api = CtxApi(ctx);
    int w = 1920, h = 1080;
    if (api && api->getSystemMetrics) {
      int sw = api->getSystemMetrics(0);
      int sh = api->getSystemMetrics(1);
      if (sw > 320 && sw < 16384 && sh > 200 && sh < 16384) { w = sw; h = sh; }
    }
    sScrW = w; sScrH = h;
  }
  Stage(ctx, 100);
  return true;
}

static int Cs2Players(sdk::GameContext* ctx, sdk::Player* out, int max) {
  __try {
    if (!ctx || !out || max <= 0) return 0;
    int offHp = (int)(intptr_t)ctx->priv[0];
    int offTeam = (int)(intptr_t)ctx->priv[1];
    int offScene = (int)(intptr_t)ctx->priv[2];
    int offOrg = (int)(intptr_t)ctx->priv[3];
    bool haveFields = (ctx->priv[4] != 0);
    int n = 0;
    for (int i = 1; i < 512 && n < max; ++i) {
      uintptr_t chunk = sdk::Read<uintptr_t>(ctx->entityList + ((0x8 * (i & 0x7FFF)) >> 9) + 0x10);
      if (!chunk) continue;
      uintptr_t ent = sdk::Read<uintptr_t>(chunk + 0x70 * (uintptr_t)(i & 0x1FF));
      if (!ent) continue;
      sdk::Player* p = &out[n];
      p->health = 0; p->team = 0; p->dormant = true;
      p->pos.x = p->pos.y = p->pos.z = 0.0f;
      p->name[0] = 0;
      if (haveFields) {
        p->health = sdk::Read<int>(ent + (uintptr_t)offHp);
        p->team = sdk::Read<int>(ent + (uintptr_t)offTeam);
        p->dormant = (p->health <= 0 || p->health > 1000);
        if (offScene >= 0 && offOrg >= 0) {
          uintptr_t node = sdk::Read<uintptr_t>(ent + (uintptr_t)offScene);
          if (node) {
            p->pos.x = sdk::Read<float>(node + (uintptr_t)offOrg);
            p->pos.y = sdk::Read<float>(node + (uintptr_t)offOrg + 4);
            p->pos.z = sdk::Read<float>(node + (uintptr_t)offOrg + 8);
          }
        }
      }
      ++n;
    }
    return n;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static bool Cs2W2S(sdk::GameContext* ctx, const sdk::Vec3& w, sdk::Vec3& s) {
  if (!ctx || !ctx->viewMatrix || !sScrW || !sScrH) return false;
  __try {
    float m[16];
    if (!sdk::ReadBuf(ctx->viewMatrix, m, sizeof(m))) return false;
    float x = m[0] * w.x + m[1] * w.y + m[2] * w.z + m[3];
    float y = m[4] * w.x + m[5] * w.y + m[6] * w.z + m[7];
    float ww = m[12] * w.x + m[13] * w.y + m[14] * w.z + m[15];
    if (ww < 0.01f) return false;
    float inv = 1.0f / ww;
    s.x = (float)sScrW * 0.5f * (1.0f + x * inv);
    s.y = (float)sScrH * 0.5f * (1.0f - y * inv);
    s.z = 0.0f;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

} // namespace

extern const sdk::IGameAdapter kCs2Adapter = { Cs2Name, Cs2Init, Cs2Players, Cs2W2S };

// ESP snapshot loop (Phase 05b-i, no hooks): every 500ms project all players,
// rewrite VacSafe-esp.txt (render log: boxes) + VacSafe-debug.txt (heartbeat).
// 120 ticks = 60s, then thread exits. Validates read->W2S->screen path.
static void WriteTickFiles(const Api* api, const char* esp, size_t espLen, const char* dbg, size_t dbgLen) {
  __try {
    char rel[32];
    vacsafe::str::CopyTo(vacsafe::str::SID_esp_rel, rel, sizeof(rel));
    char tmp[MAX_PATH] = {0};
    DWORD tn = api->getTempPath(sizeof(tmp) - 32, tmp);
    if (tn && tn < sizeof(tmp) - 32) {
      char* dst = tmp + tn;
      for (size_t k = 0; rel[k]; ++k) *dst++ = rel[k];
      *dst = 0;
      HANDLE f = api->createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (f != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        api->writeFile(f, esp, (DWORD)espLen, &w, nullptr);
        api->close(f);
      }
    }
    // debug heartbeat reuses a sibling filename
    {
      char tmp2[MAX_PATH] = {0};
      DWORD tn2 = api->getTempPath(sizeof(tmp2) - 40, tmp2);
      if (tn2 && tn2 < sizeof(tmp2) - 40) {
        char rel2[32];
        vacsafe::str::CopyTo(vacsafe::str::SID_dbg_rel, rel2, sizeof(rel2));
        char* d2 = tmp2 + tn2;
        for (size_t k = 0; rel2[k]; ++k) *d2++ = rel2[k];
        *d2 = 0;
        HANDLE f = api->createFile(tmp2, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
          DWORD w = 0;
          api->writeFile(f, dbg, (DWORD)dbgLen, &w, nullptr);
          api->close(f);
        }
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void AppInt(char* dst, size_t cap, size_t* pos, int v) {
  char nb[12]; int nn = 0;
  if (v < 0) { if (*pos + 1 < cap) dst[(*pos)++] = '-'; v = -v; }
  if (!v) nb[nn++] = '0';
  while (v > 0 && nn < 11) { nb[nn++] = (char)('0' + v % 10); v /= 10; }
  while (nn > 0 && *pos + 1 < cap) dst[(*pos)++] = nb[--nn];
}

void EspLog(sdk::GameContext* ctx, const Api* api) {
  if (!ctx || !api || !api->sleepMs) return;
  for (int tick = 0; tick < 120; ++tick) {
    api->sleepMs(500);
    __try {
      sdk::Player ps[16]{};
      int n = kCs2Adapter.GetPlayers(ctx, ps, 16);
      if (n < 0) n = 0;
      if (n > 16) n = 16;
      char out[2048]{};
      size_t p = 0;
      // render log: "tick=N n=M" then per visible player "i fx fy hx hy w h hp team"
      AppId(out, sizeof(out), &p, vacsafe::str::SID_t_tick);
      AppInt(out, sizeof(out), &p, tick);
      AppId(out, sizeof(out), &p, vacsafe::str::SID_t_n);
      AppInt(out, sizeof(out), &p, n);
      AppStr(out, sizeof(out), &p, "\r\n");
      int drawn = 0, skipped = 0;
      for (int i = 0; i < n && p + 80 < sizeof(out); ++i) {
        sdk::Vec3 feet{}, head{}, sf{}, sh{};
        feet = ps[i].pos;
        head = ps[i].pos;
        head.z += 72.0f;
        bool vf = kCs2Adapter.WorldToScreen(ctx, feet, sf);
        bool vh = kCs2Adapter.WorldToScreen(ctx, head, sh);
        if (!vf || !vh) { ++skipped; continue; }
        int fx = (int)sf.x, fy = (int)sf.y, hx = (int)sh.x, hy = (int)sh.y;
        int h = fy - hy;
        if (h <= 0 || h > 4096) { ++skipped; continue; }
        int w = h / 2;
        int vals[8] = { i, fx, fy, hx, hy, w, h, ps[i].health };
        for (int k = 0; k < 8; ++k) {
          if (k) AppStr(out, sizeof(out), &p, " ");
          AppInt(out, sizeof(out), &p, vals[k]);
        }
        AppStr(out, sizeof(out), &p, " ");
        AppInt(out, sizeof(out), &p, ps[i].team);
        AppStr(out, sizeof(out), &p, "\r\n");
        ++drawn;
      }
      out[p] = 0;
      char dbg[128]{};
      size_t q = 0;
      AppId(dbg, sizeof(dbg), &q, vacsafe::str::SID_t_tick);
      AppInt(dbg, sizeof(dbg), &q, tick);
      AppId(dbg, sizeof(dbg), &q, vacsafe::str::SID_t_n);
      AppInt(dbg, sizeof(dbg), &q, n);
      AppId(dbg, sizeof(dbg), &q, vacsafe::str::SID_t_drawn);
      AppInt(dbg, sizeof(dbg), &q, drawn);
      AppId(dbg, sizeof(dbg), &q, vacsafe::str::SID_t_skip);
      AppInt(dbg, sizeof(dbg), &q, skipped);
      AppStr(dbg, sizeof(dbg), &q, "\r\n");
      WriteTickFiles(api, out, p, dbg, q);
    } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
  }
}

} // namespace vacsafe
