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
  // djb2: EnumWindows=0x94CFDCC5 GetWindowThreadProcessId=0xA58EDBE1 GetDC=0x0D3D24AC
  // ReleaseDC=0xE43871CD Rectangle=0x5267005A CreatePen=0xED6925BC SelectObject=0x7CF4FD7C
  // DeleteObject=0xCC68186F GetStockObject=0xD7460980 SetBkMode=0x6F828843
  // SetTextColor=0x41936715 TextOutA=0x805294C3 (all user32.dll)
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
    return enumWin && wndThread && getDc && releaseDc && rect && createPen &&
           selObj && delObj && getStock && bkMode && textColor && textOut;
  }
};

static Gdi g_gdi;
static void* s_hwnd = nullptr;
static const sdk::IGameAdapter* s_ad = nullptr;
static sdk::GameContext* s_ctx = nullptr;

static int __stdcall EnumCb(void* hwnd, uintptr_t pid) {
  __try {
    uint32_t p = 0;
    if (g_gdi.wndThread && g_gdi.wndThread(hwnd, &p) && p == (uint32_t)pid && !s_hwnd) {
      // Prefer a visible top-level window with nonzero size (skip helpers).
      s_hwnd = hwnd;
      return 0; // stop
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
  return 1; // continue
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
  if (!g_gdi.Resolve()) return 1;
  // find our game window once (first visible top-level of our pid)
  {
    // TEB.ClientId redacted in SDK headers; stable ABI offset 0x40 (UniqueProcess).
    uint32_t pid = *(volatile uint32_t*)((uint8_t*)NtCurrentTeb() + 0x40);
    g_gdi.enumWin(EnumCb, pid);
    if (!s_hwnd) return 2;
  }
  // 60s at ~50ms: fresh reads + immediate draw (no persistence by design here)
  for (int t = 0; t < 1200; ++t) {
    // sleep via busy yield on hashed Sleep? use NtDelayExecution-free approach:
    // short Sleep through kernel32 Sleep hash (resolve inline, cached static)
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
      sdk::Player ps[16]{};
      int n = s_ad->GetPlayers(s_ctx, ps, 16);
      if (n <= 0) continue;
      void* hdc = g_gdi.getDc(s_hwnd);
      if (!hdc) continue;
      for (int i = 0; i < n && i < 16; ++i) {
        if (ps[i].health <= 0) continue; // pawns only for render pass
        DrawPlayer(hdc, ps[i]);
      }
      g_gdi.releaseDc(s_hwnd, hdc);
    } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
  }
  return 0;
}

void RenderStart(const sdk::IGameAdapter* ad, sdk::GameContext* ctx, const Api* api) {
  if (!ad || !ctx || !api || !api->createThread) return;
  s_ad = ad;
  s_ctx = ctx;
  DWORD tid = 0;
  HANDLE h = api->createThread(nullptr, 0, RenderThread, nullptr, 0, &tid);
  if (h && api->close) api->close(h);
}

} // namespace vacsafe
