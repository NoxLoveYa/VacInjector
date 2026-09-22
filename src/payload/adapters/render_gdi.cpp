#include "game_adapter.h"
#include "nt_api.h"
#include "peb.h"
#include "strings.inc"
#include "stealth.h"
#include "../api.h"
#include <windows.h>
#include <winternl.h>

// Internal GDI render pass (Phase 05b-ii validation build). NO hooks, NO overlay
// window: draws boxes + hp text directly onto the game window DC from our hidden
// thread at 50ms cadence. Flickers under Present (expected); proves positions on
// screen for eyeball confirmation. The persistent DXGI Present hook replaces this.
// CRT-free: hashed user32 only, manual loops, static POD state.
namespace vacsafe {

typedef int (WINAPI* EnumWindowsFn)(void*, uintptr_t);
typedef uint32_t (WINAPI* GetWndThreadFn)(void*, uint32_t*);
typedef void* (WINAPI* GetDcFn)(void*);
typedef int (WINAPI* ReleaseDcFn)(void*, void*);
typedef int (WINAPI* RectFn)(void*, int, int, int, int);
typedef void* (WINAPI* CreatePenFn)(int, int, uint32_t);
typedef void* (WINAPI* SelObjFn)(void*, void*);
typedef int (WINAPI* DelObjFn)(void*);
typedef void* (WINAPI* GetStockFn)(int);
typedef int (WINAPI* BkModeFn)(void*, int);
typedef uint32_t (WINAPI* TextColorFn)(void*, uint32_t);
typedef int (WINAPI* TextOutFn)(void*, int, int, const char*, int);
typedef int (WINAPI* MoveToFn)(void*, int, int, void*);
typedef int (WINAPI* LineToFn)(void*, int, int);
typedef int (WINAPI* IsVisFn)(void*);
typedef int (WINAPI* GetMetricsFn)(int);
typedef int (WINAPI* GetRectFn)(void*, void*);
typedef uint32_t (WINAPI* GetLastErrFn)();

struct Gdi {
  EnumWindowsFn enumWin = nullptr;
  GetWndThreadFn wndThread = nullptr;
  GetDcFn getDc = nullptr;
  ReleaseDcFn releaseDc = nullptr;
  RectFn rect = nullptr;
  CreatePenFn createPen = nullptr;
  SelObjFn selObj = nullptr;
  DelObjFn delObj = nullptr;
  GetStockFn getStock = nullptr;
  BkModeFn bkMode = nullptr;
  TextColorFn textColor = nullptr;
  TextOutFn textOut = nullptr;
  MoveToFn moveTo = nullptr;
  LineToFn lineTo = nullptr;
  IsVisFn isVis = nullptr;
  GetMetricsFn getMetrics = nullptr;
  GetRectFn getRect = nullptr;
  // djb2: EnumWindows=0x94CFDCC5 GetWindowThreadProcessId=0xA58EDBE1 GetDC=0x0D3D24AC
  // ReleaseDC=0xE43871CD Rectangle=0x5267005A CreatePen=0xED6925BC SelectObject=0x7CF4FD7C
  // DeleteObject=0xCC68186F GetStockObject=0xD7460980 SetBkMode=0x6F828843
  // SetTextColor=0x41936715 TextOutA=0x805294C3 MoveToEx=0x0694FFDC LineTo=0xC0D12C10
  // IsWindowVisible=0xE35AC807 GetSystemMetrics=0xA988C1A1 GetWindowRect=0xF68C840B (all user32.dll)
  bool Resolve() {
    wchar_t u32[16];
    vacsafe::str::CopyToW(vacsafe::str::SID_mod_user32, u32, 16);
    enumWin = (EnumWindowsFn)nt::GetProcByHash(u32, 0x94CFDCC5);
    wndThread = (GetWndThreadFn)nt::GetProcByHash(u32, 0xA58EDBE1);
    getDc = (GetDcFn)nt::GetProcByHash(u32, 0x0D3D24AC);
    releaseDc = (ReleaseDcFn)nt::GetProcByHash(u32, 0xE43871CD);
    rect = (RectFn)nt::GetProcByHash(u32, 0x5267005A);
    createPen = (CreatePenFn)nt::GetProcByHash(u32, 0xED6925BC);
    selObj = (SelObjFn)nt::GetProcByHash(u32, 0x7CF4FD7C);
    delObj = (DelObjFn)nt::GetProcByHash(u32, 0xCC68186F);
    getStock = (GetStockFn)nt::GetProcByHash(u32, 0xD7460980);
    bkMode = (BkModeFn)nt::GetProcByHash(u32, 0x6F828843);
    textColor = (TextColorFn)nt::GetProcByHash(u32, 0x41936715);
    textOut = (TextOutFn)nt::GetProcByHash(u32, 0x805294C3);
    moveTo = (MoveToFn)nt::GetProcByHash(u32, 0x0694FFDC);
    lineTo = (LineToFn)nt::GetProcByHash(u32, 0xC0D12C10);
    isVis = (IsVisFn)nt::GetProcByHash(u32, 0xE35AC807);
    getMetrics = (GetMetricsFn)nt::GetProcByHash(u32, 0xA988C1A1);
    getRect = (GetRectFn)nt::GetProcByHash(u32, 0xF68C840B);
    return enumWin && wndThread && getDc && releaseDc && rect && createPen &&
           selObj && delObj && getStock && bkMode && textColor && textOut &&
           moveTo && lineTo && isVis && getMetrics && getRect;
  }
};

static Gdi g_gdi;
static void* s_hwnd = nullptr;
static const sdk::IGameAdapter* s_ad = nullptr;
static sdk::GameContext* s_ctx = nullptr;
static const Api* s_api = nullptr;
static uintptr_t s_base = 0;
static int s_frames = 0;
static int s_drawnTotal = 0;

static int __stdcall EnumCb(void* hwnd, uintptr_t pid) {
  __try {
    uint32_t p = 0;
    if (g_gdi.wndThread && g_gdi.wndThread(hwnd, &p) && p == (uint32_t)pid && !s_hwnd) {
      // Visible AND nonzero-area top-level only (helpers are hidden or 0-size).
      if (g_gdi.isVis && !g_gdi.isVis(hwnd)) return 1;
      if (g_gdi.getRect) {
        struct R { int l, t, r, b; } rc{};
        if (g_gdi.getRect(hwnd, &rc) && (rc.r - rc.l) > 200 && (rc.b - rc.t) > 200) {
          s_hwnd = hwnd;
          return 0;
        }
        return 1;
      }
      s_hwnd = hwnd;
      return 0; // stop
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
  return 1; // continue
}

// Static overlay: crosshair + tag + fixed test box. Independent of entity data:
// if this never shows, the DC/HWND path is broken (not the data path).
static void DrawStatic(void* hdc, int cx, int cy) {
  void* pen = g_gdi.createPen(0 /*PS_SOLID*/, 2, 0x00FFFF);
  if (!pen) return;
  void* oldPen = g_gdi.selObj(hdc, pen);
  g_gdi.moveTo(hdc, cx - 12, cy, nullptr);
  g_gdi.lineTo(hdc, cx + 12, cy);
  g_gdi.moveTo(hdc, cx, cy - 12, nullptr);
  g_gdi.lineTo(hdc, cx, cy + 12);
  void* hollow = g_gdi.getStock(5 /*HOLLOW_BRUSH*/);
  void* oldBr = hollow ? g_gdi.selObj(hdc, hollow) : nullptr;
  g_gdi.rect(hdc, 100, 100, 220, 260); // fixed test box, top-left
  char tag[16];
  vacsafe::str::CopyTo(vacsafe::str::SID_t_tag, tag, sizeof(tag));
  int tn = 0;
  while (tag[tn]) ++tn;
  g_gdi.bkMode(hdc, 1 /*TRANSPARENT*/);
  g_gdi.textColor(hdc, 0x00FFFF);
  g_gdi.textOut(hdc, 100, 80, tag, tn);
  if (oldPen) g_gdi.selObj(hdc, oldPen);
  if (oldBr) g_gdi.selObj(hdc, oldBr);
  g_gdi.delObj(pen);
}

static void RenderFileName(const Api* api, char* out, size_t cap) {
  // Per-image status file: VacSafe-render-<base8>.txt. Shared filenames tear
  // when several images are injected (each overwrites the other).
  char rel[32];
  vacsafe::str::CopyTo(vacsafe::str::SID_render_rel, rel, sizeof(rel));
  char tmp[MAX_PATH] = {0};
  DWORD tn = api->getTempPath(sizeof(tmp) - 48, tmp);
  if (!tn || tn >= sizeof(tmp) - 48) { if (cap) out[0] = 0; return; }
  char* dst = tmp + tn;
  for (size_t k = 0; rel[k]; ++k) *dst++ = rel[k];
  *dst = 0;
  // insert "-<base8>" before ".txt": find the dot
  char* dot = tmp;
  while (*dot && *dot != '.') ++dot;
  if (*dot) {
    char tail[16];
    size_t tl = 0;
    while (dot[tl] && tl + 1 < sizeof(tail)) { tail[tl] = dot[tl]; ++tl; }
    tail[tl] = 0;
    *dst++ = '-';
    uint64_t v = (uint64_t)s_base;
    const char* dig = "0123456789ABCDEF";
    bool st = false;
    for (int sh = 28; sh >= 0; sh -= 4) {
      int d = (int)((v >> sh) & 0xF);
      if (d || st || sh == 0) { st = true; *dst++ = dig[d]; }
    }
    for (size_t k = 0; tail[k]; ++k) *dst++ = tail[k];
    *dst = 0;
  }
  size_t i = 0;
  for (; tmp[i] && i + 1 < cap; ++i) out[i] = tmp[i];
  out[i] = 0;
}

static void WriteRenderStatus(const Api* api, void* hwnd, int frames, int drawn) {
  __try {
  char tmp[MAX_PATH] = {0};
  RenderFileName(api, tmp, sizeof(tmp));
  if (!tmp[0]) return;
    char out[128]{};
    size_t p = 0;
    // "base=0x.. hwnd=0x.. frames=N drawn=M": identifies which image writes.
    const char* bb = "base=";
    while (*bb && p + 1 < sizeof(out)) out[p++] = *bb++;
    {
      char hx0[20];
      uint64_t v0 = (uint64_t)s_base;
      const char* dig0 = "0123456789ABCDEF";
      out[p++] = '0'; out[p++] = 'x';
      bool st0 = false;
      for (int sh = 60; sh >= 0; sh -= 4) {
        int d = (int)((v0 >> sh) & 0xF);
        if (d || st0 || sh == 0) { st0 = true; if (p + 1 < sizeof(out)) out[p++] = dig0[d]; }
      }
    }
    const char* h = " hwnd=";
    while (*h && p + 1 < sizeof(out)) out[p++] = *h++;
    char hx[20];
    uint64_t v = (uint64_t)(uintptr_t)hwnd;
    const char* dig = "0123456789ABCDEF";
    out[p++] = '0'; out[p++] = 'x';
    bool st = false;
    for (int sh = 60; sh >= 0; sh -= 4) {
      int d = (int)((v >> sh) & 0xF);
      if (d || st || sh == 0) { st = true; if (p + 1 < sizeof(out)) out[p++] = dig[d]; }
    }
    const char* f = " frames=";
    while (*f && p + 1 < sizeof(out)) out[p++] = *f++;
    char nb[12]; int nn = 0, tv = frames;
    if (!tv) nb[nn++] = '0';
    while (tv > 0 && nn < 11) { nb[nn++] = (char)('0' + tv % 10); tv /= 10; }
    while (nn > 0 && p + 1 < sizeof(out)) out[p++] = nb[--nn];
    const char* dr = " drawn=";
    while (*dr && p + 1 < sizeof(out)) out[p++] = *dr++;
    nn = 0; tv = drawn;
    if (!tv) nb[nn++] = '0';
    while (tv > 0 && nn < 11) { nb[nn++] = (char)('0' + tv % 10); tv /= 10; }
    while (nn > 0 && p + 1 < sizeof(out)) out[p++] = nb[--nn];
    if (p + 2 < sizeof(out)) { out[p++] = '\r'; out[p++] = '\n'; }
    out[p] = 0;
    HANDLE fh = api->createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    api->writeFile(fh, out, (DWORD)p, &w, nullptr);
    api->close(fh);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void WriteRenderStatusGLE(const Api* api, void* hwnd, int frames, int drawn, uint32_t gle) {
  __try {
    WriteRenderStatus(api, hwnd, frames, drawn);
    // append " gle=N" by re-read + rewrite (diag only, runs once)
    char tmp[MAX_PATH] = {0};
    RenderFileName(api, tmp, sizeof(tmp));
    if (!tmp[0]) return;
    char ob[160]{};
    size_t q = 0;
    HANDLE fr = api->createFile(tmp, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fr != INVALID_HANDLE_VALUE) {
      DWORD r = 0;
      api->readFile(fr, ob, (DWORD)sizeof(ob) - 24, &r, nullptr);
      api->close(fr);
      q = r;
    }
    char gb[16];
    vacsafe::str::CopyTo(vacsafe::str::SID_t_gle, gb, sizeof(gb));
    for (size_t k = 0; gb[k] && q + 1 < sizeof(ob); ++k) ob[q++] = gb[k];
    char nb[12]; int nn = 0;
    uint32_t v = gle;
    if (!v) nb[nn++] = '0';
    while (v > 0 && nn < 10) { nb[nn++] = (char)('0' + v % 10); v /= 10; }
    while (nn > 0 && q + 1 < sizeof(ob)) ob[q++] = nb[--nn];
    if (q + 2 < sizeof(ob)) { ob[q++] = '\r'; ob[q++] = '\n'; }
    ob[q] = 0;
    HANDLE fw = api->createFile(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fw == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    api->writeFile(fw, ob, (DWORD)q, &w, nullptr);
    api->close(fw);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void DrawPlayer(void* hdc, const sdk::Player& pl) {
  sdk::Vec3 sf{}, sh{};
  sdk::Vec3 feet = pl.pos;
  sdk::Vec3 head = pl.pos;
  head.z += 72.0f;
  if (!s_ad->WorldToScreen(s_ctx, feet, sf)) return;
  if (!s_ad->WorldToScreen(s_ctx, head, sh)) return;
  int fx = (int)sf.x, fy = (int)sf.y, hx = (int)sh.x, hy = (int)sh.y;
  int h = fy - hy;
  if (h <= 0 || h > 4096) return;
  int w = h / 2;
  int x0 = fx - w / 2, x1 = fx + w / 2;
  if (x1 < -100 || x0 > 10000 || hy < -100 || fy > 10000) return; // off-screen
  uint32_t col = (pl.team == 3) ? 0x00FF00 : (pl.team == 2) ? 0x0000FF : 0xFFFFFF;
  void* pen = g_gdi.createPen(0 /*PS_SOLID*/, 2, col);
  if (!pen) return;
  void* hollow = g_gdi.getStock(5 /*HOLLOW_BRUSH*/);
  void* oldPen = g_gdi.selObj(hdc, pen);
  void* oldBr = hollow ? g_gdi.selObj(hdc, hollow) : nullptr;
  g_gdi.rect(hdc, x0, hy, x1, fy);
  // hp text above box
  char hp[12];
  int v = pl.health < 0 ? 0 : (pl.health > 999 ? 999 : pl.health);
  int nn = 0;
  if (!v) hp[nn++] = '0';
  while (v > 0 && nn < 10) { hp[nn++] = (char)('0' + v % 10); v /= 10; }
  // reverse in place
  for (int a = 0, b = nn - 1; a < b; ++a, --b) { char t = hp[a]; hp[a] = hp[b]; hp[b] = t; }
  g_gdi.bkMode(hdc, 1 /*TRANSPARENT*/);
  g_gdi.textColor(hdc, col);
  g_gdi.textOut(hdc, x0, hy - 16, hp, nn);
  if (oldPen) g_gdi.selObj(hdc, oldPen);
  if (oldBr) g_gdi.selObj(hdc, oldBr);
  g_gdi.delObj(pen);
}

static DWORD WINAPI RenderThread(LPVOID p) {
  (void)p;
  vacsafe::stealth::HideCurrentThreadPub();
  // Startup stages to render.txt (R1 resolve, R2 hwnd, then frames): pinpoints
  // silent early death (no markers = died before first status write).
  if (!g_gdi.Resolve()) {
    if (s_api) WriteRenderStatus(s_api, nullptr, -1, 0);
    return 1;
  }
  // find our game window once (first visible top-level of our pid)
  {
    // TEB.ClientId redacted in SDK headers; stable ABI offset 0x40 (UniqueProcess).
    uint32_t pid = *(volatile uint32_t*)((uint8_t*)NtCurrentTeb() + 0x40);
    g_gdi.enumWin(EnumCb, pid);
    if (!s_hwnd && s_api) WriteRenderStatus(s_api, nullptr, -2, 0);
    if (!s_hwnd) return 2;
  }
  // 60s at ~50ms: static overlay EVERY frame (independent of entities),
  // then entity boxes. Static proving the DC path even with n=0.
  int cx = 640, cy = 360;
  if (g_gdi.getMetrics) {
    int w = g_gdi.getMetrics(0);
    int h = g_gdi.getMetrics(1);
    if (w > 320 && w < 16384 && h > 200 && h < 16384) { cx = w / 2; cy = h / 2; }
  }
  for (int t = 0; t < 1200; ++t) {
    // short Sleep through hashed kernel32 Sleep (resolve inline, cached static)
    {
      static void* sSleep = nullptr;
      if (!sSleep) {
        wchar_t k32[16];
        vacsafe::str::CopyToW(vacsafe::str::SID_mod_kernel32, k32, 16);
        sSleep = nt::GetProcByHash(k32, 0x0E19E5FE);
      }
      if (sSleep) ((void (WINAPI*)(uint32_t))sSleep)(50);
    }
    __try {
      if (!s_ad || !s_ctx) continue;
      void* hdc = g_gdi.getDc(s_hwnd);
      if (!hdc) continue;
      DrawStatic(hdc, cx, cy);
      int drawnHere = 0;
      sdk::Player ps[16]{};
      int n = s_ad->GetPlayers(s_ctx, ps, 16);
      for (int i = 0; i < n && i < 16; ++i) {
        if (ps[i].health <= 0) continue; // pawns only for render pass
        DrawPlayer(hdc, ps[i]);
        ++drawnHere;
      }
      g_gdi.releaseDc(s_hwnd, hdc);
      ++s_frames;
      s_drawnTotal += drawnHere;
      if ((t & 15) == 0 && s_api) WriteRenderStatus(s_api, s_hwnd, s_frames, s_drawnTotal);
    } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
  }
  return 0;
}

void RenderStart(const sdk::IGameAdapter* ad, sdk::GameContext* ctx, const Api* api, void* base) {
  if (!ad || !ctx || !api || !api->createThread) return;
  s_ad = ad;
  s_ctx = ctx;
  s_api = api;
  s_base = (uintptr_t)base;
  DWORD tid = 0;
  HANDLE h = api->createThread(nullptr, 0, RenderThread, nullptr, 0, &tid);
  // R-3 marker (even on failure): proves whether the thread was ever created.
  // On failure also logs GetLastError (djb2 GetLastError=0x2082EAE3).
  uint32_t gle = 0;
  {
    wchar_t k32[16];
    vacsafe::str::CopyToW(vacsafe::str::SID_mod_kernel32, k32, 16);
    void* f = nt::GetProcByHash(k32, 0x2082EAE3);
    if (f) gle = ((GetLastErrFn)f)();
  }
  WriteRenderStatusGLE(api, h, -3, (int)tid, gle);
  if (h && api->close) api->close(h);
}

} // namespace vacsafe
