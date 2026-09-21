#include "game_adapter.h"
#include "nt_api.h"
#include "peb.h"
#include "obf.h"
#include "../api.h"
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

static const vacsafe::Api* CtxApi(sdk::GameContext* ctx) {
  if (!ctx) return nullptr;
  return (const vacsafe::Api*)(uintptr_t)ctx->priv[7];
}

// Minimal stage writer: "stage=N exe=X [a=0x.. b=0x..] err=Y". Overwrites proof file.
static void StageDetail(sdk::GameContext* ctx, uint32_t n, uint64_t a, uint64_t b) {
  if (!ctx) return;
  ctx->priv[5] = n;
  __try {
    const vacsafe::Api* api = CtxApi(ctx);
    if (!api || !api->createFile || !api->getTempPath) return;
    VACSAFE_OBF_BUF(rel, "VacSafe-cs2.txt");
    char tmp[MAX_PATH] = {0};
    DWORD tn = api->getTempPath(sizeof(tmp) - (DWORD)sizeof(rel) - 1, tmp);
    if (!tn || tn >= sizeof(tmp) - sizeof(rel) - 1) return;
    char* dst = tmp + tn;
    for (size_t i = 0; rel[i]; ++i) *dst++ = rel[i];
    *dst = 0;
    char out[256]{};
    size_t p = 0;
    const char* pre = "stage=";
    while (*pre && p + 1 < sizeof(out)) out[p++] = *pre++;
    char nb[12]; int nn = 0;
    uint32_t v = n;
    if (!v) nb[nn++] = '0';
    while (v && nn < 11) { nb[nn++] = (char)('0' + v % 10); v /= 10; }
    while (nn > 0 && p + 1 < sizeof(out)) out[p++] = nb[--nn];
    const char* mid = " exe=";
    while (*mid && p + 1 < sizeof(out)) out[p++] = *mid++;
    for (size_t i = 0; ctx->exeName[i] && p + 1 < sizeof(out); ++i) out[p++] = ctx->exeName[i];
    if (a || b) {
      const char* ap = " a=";
      while (*ap && p + 1 < sizeof(out)) out[p++] = *ap++;
      char hx[20];
      sdk::U64ToHex(hx, sizeof(hx), a);
      for (size_t i = 0; hx[i] && p + 1 < sizeof(out); ++i) out[p++] = hx[i];
      const char* bp = " b=";
      while (*bp && p + 1 < sizeof(out)) out[p++] = *bp++;
      sdk::U64ToHex(hx, sizeof(hx), b);
      for (size_t i = 0; hx[i] && p + 1 < sizeof(out); ++i) out[p++] = hx[i];
    }
    if (ctx->err[0]) {
      const char* e = " err=";
      while (*e && p + 1 < sizeof(out)) out[p++] = *e++;
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

// --- signatures (client.dll, x64; cs2-dumper lineage; guarded at runtime) ---
struct Sig { const uint8_t* pat; const char* mask; size_t len; size_t ripLen; size_t ripOff; const char* what; };
static const uint8_t kEntPat[] = {0x48,0x8B,0x0D,0,0,0,0, 0x48,0x89,0x7C,0x24,0, 0x8B,0xFA,0xC1,0xEB};
static const char kEntMask[] = "xxx????xxxx?xxxx";
static const uint8_t kLpPat[] = {0x48,0x8D,0x05,0,0,0,0, 0xC3,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC, 0x48,0x83,0xEC,0, 0x8B,0x0D};
static const char kLpMask[] = "xxx????xxxxxxxxxxxx?xx";
static const uint8_t kVmPat[] = {0x48,0x8D,0x0D,0,0,0,0, 0x48,0xC1,0xE0,0x06};
static const char kVmMask[] = "xxx????xxx";

static bool ScanGlobal(sdk::GameContext* ctx, const uint8_t* pat, const char* mask, size_t len,
                       const char* what, uintptr_t* out) {
  uintptr_t m = sdk::PatternScan(ctx->mod.clientBase, ctx->mod.clientSize, pat, mask, len);
  if (!m) {
    // Include module bounds: distinguishes wrong-base/size from true sig drift.
    char eb[sdk::kMaxErrLen];
    size_t i = 0;
    const char* p = "sig stale: ";
    while (*p && i + 1 < sizeof(eb)) eb[i++] = *p++;
    p = what;
    while (*p && i + 1 < sizeof(eb)) eb[i++] = *p++;
    p = " base=";
    while (*p && i + 1 < sizeof(eb)) eb[i++] = *p++;
    char hx[20];
    sdk::U64ToHex(hx, sizeof(hx), ctx->mod.clientBase);
    for (size_t k = 0; hx[k] && i + 1 < sizeof(eb); ++k) eb[i++] = hx[k];
    p = " size=";
    while (*p && i + 1 < sizeof(eb)) eb[i++] = *p++;
    sdk::U64ToHex(hx, sizeof(hx), ctx->mod.clientSize);
    for (size_t k = 0; hx[k] && i + 1 < sizeof(eb); ++k) eb[i++] = hx[k];
    // map forensics survive into the miss line (stage file overwrites per stage)
    p = " mz=";
    while (*p && i + 1 < sizeof(eb)) eb[i++] = *p++;
    sdk::U64ToHex(hx, sizeof(hx), ctx->priv[8]);
    for (size_t k = 2; hx[k] && i + 1 < sizeof(eb); ++k) eb[i++] = hx[k];
    p = " t=";
    while (*p && i + 1 < sizeof(eb)) eb[i++] = *p++;
    sdk::U64ToHex(hx, sizeof(hx), ctx->priv[9]);
    for (size_t k = 2; hx[k] && i + 1 < sizeof(eb); ++k) eb[i++] = hx[k];
    p = " ninst=";
    while (*p && i + 1 < sizeof(eb)) eb[i++] = *p++;
    sdk::U64ToHex(hx, sizeof(hx), ctx->priv[6]);
    for (size_t k = 2; hx[k] && i + 1 < sizeof(eb); ++k) eb[i++] = hx[k];
    p = " pm=";
    while (*p && i + 1 < sizeof(eb)) eb[i++] = *p++;
    sdk::U64ToHex(hx, sizeof(hx), ctx->priv[11]);
    for (size_t k = 2; hx[k] && i + 1 < sizeof(eb); ++k) eb[i++] = hx[k];
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
      sdk::SetErr(ctx, "schema vtable[13] outside modules (stale index?)");
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
      sdk::SetErr(ctx, "schema vtable[2] outside modules (stale index?)");
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
  if (!ctx->mod.schemaBase) { sdk::SetErr(ctx, "schemasystem.dll absent"); return false; }
  Stage(ctx, 60);
  // Range-gate CreateInterface too: must live inside schemasystem.dll.
  void* ci = nt::GetProcByName((void*)ctx->mod.schemaBase, VACSAFE_OBF("CreateInterface"));
  if (!ci || !nt::AddressInModules((uintptr_t)ci)) { sdk::SetErr(ctx, "CreateInterface missing in schemasystem"); return false; }
  typedef void* (*CiFn)(const char*, int*);
  void* sys = nullptr;
  __try { sys = ((CiFn)ci)(VACSAFE_OBF("SchemaSystem_001"), nullptr); }
  __except (EXCEPTION_EXECUTE_HANDLER) { sys = nullptr; }
  if (!sys) { sdk::SetErr(ctx, "SchemaSystem_001 capture failed"); return false; }
  Stage(ctx, 65);
  void* scope = CallScope(ctx, sys, VACSAFE_OBF("client.dll"));
  if (!scope) { if (!ctx->err[0]) sdk::SetErr(ctx, "schema scope client.dll missing (vtable stale?)"); Stage(ctx, 69); return false; }
  Stage(ctx, 70);
  void* pawn = CallClass(ctx, scope, VACSAFE_OBF("C_CSPlayerPawn"));
  if (!pawn) { if (!ctx->err[0]) sdk::SetErr(ctx, "C_CSPlayerPawn missing in schema"); Stage(ctx, 79); return false; }
  Stage(ctx, 80);
  so->offHealth = FindField(pawn, VACSAFE_OBF("m_iHealth"));
  so->offTeam = FindField(pawn, VACSAFE_OBF("m_iTeamNum"));
  so->offScene = FindField(pawn, VACSAFE_OBF("m_pGameSceneNode"));
  void* node = CallClass(ctx, scope, VACSAFE_OBF("CGameSceneNode"));
  if (node) so->offOrigin = FindField(node, VACSAFE_OBF("m_vecOrigin"));
  so->ok = (so->offHealth >= 0 && so->offTeam >= 0);
  Stage(ctx, 90);
  return true;
}

// --- entity list walk (no schema needed): count non-null identities 1..512 ---
static int CountEntities(sdk::GameContext* ctx) {
  __try {
    if (!ctx->entityList) return 0;
    int n = 0;
    for (int i = 1; i < 512; ++i) {
      uintptr_t chunk = sdk::Read<uintptr_t>(ctx->entityList + ((0x8 * (i & 0x7FFF)) >> 9) + 0x10);
      if (!chunk) continue;
      uintptr_t ent = sdk::Read<uintptr_t>(chunk + 0x70 * (uintptr_t)(i & 0x1FF));
      if (ent) ++n;
    }
    return n;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static const char* Cs2Name() { return "cs2/source2"; }

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
    const char* pre = "map mz=";
    while (*pre && p + 1 < sizeof(eb)) eb[p++] = *pre++;
    if (okMz) {
      const char* dig = "0123456789ABCDEF";
      eb[p++] = dig[(mz[0] >> 4) & 0xF]; eb[p++] = dig[mz[0] & 0xF];
      eb[p++] = dig[(mz[1] >> 4) & 0xF]; eb[p++] = dig[mz[1] & 0xF];
    } else { eb[p++] = '?'; eb[p++] = '?'; }
    const char* mid = " t=";
    while (*mid && p + 1 < sizeof(eb)) eb[p++] = *mid++;
    if (okT) {
      const char* dig = "0123456789ABCDEF";
      for (int i = 0; i < 8 && p + 2 < sizeof(eb); ++i) {
        eb[p++] = dig[(t0[i] >> 4) & 0xF]; eb[p++] = dig[t0[i] & 0xF];
      }
    } else {
      const char* q = "UNREADABLE";
      while (*q && p + 1 < sizeof(eb)) eb[p++] = *q++;
    }
    const char* cc = " ninst=";
    while (*cc && p + 1 < sizeof(eb)) eb[p++] = *cc++;
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
  if (!ScanGlobal(ctx, kEntPat, kEntMask, sizeof(kEntPat), "dwEntityList", &ctx->entityList)) { Stage(ctx, 29); return false; }
  Stage(ctx, 30);
  if (!ScanGlobal(ctx, kLpPat, kLpMask, sizeof(kLpPat), "dwLocalPlayerPawn", &ctx->localPlayer)) { Stage(ctx, 39); return false; }
  Stage(ctx, 40);
  if (!ScanGlobal(ctx, kVmPat, kVmMask, sizeof(kVmPat), "dwViewMatrix", &ctx->viewMatrix)) { Stage(ctx, 49); return false; }
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
  (void)ctx; (void)w; (void)s;
  return false; // renderer lands next iteration (ESP); count+fields prove the loop now
}

} // namespace

extern const sdk::IGameAdapter kCs2Adapter = { Cs2Name, Cs2Init, Cs2Players, Cs2W2S };

} // namespace vacsafe
