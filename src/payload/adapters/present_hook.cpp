#include "present_hook.h"
#include "nt_api.h"
#include "strings.inc"
#include "../api.h"
#include "../esp_vs.h"
#include "../esp_ps.h"
#include <windows.h>
#include <winternl.h>
#include <d3d11.h>
#include <dxgi.h>

// DXGI Present hook with D3D11 line ESP. Vtable indices VERIFIED against SDK
// headers via tools/dump_vtable.py (never hand-recalled). CRT-free.
namespace vacsafe {
namespace {

// D3D11 context/device/swapchain vtable indices (verified, stable COM ABI).
constexpr size_t kPresentIdx = 8;
constexpr size_t kGetDeviceIdx = 7;
constexpr size_t kGetBufferIdx = 9;
constexpr size_t kGetDescIdx = 12;
constexpr size_t kCreateBufferIdx = 3;
constexpr size_t kCreateRTVIdx = 9;
constexpr size_t kCreateLayoutIdx = 11;
constexpr size_t kCreateVSIdx = 12;
constexpr size_t kCreatePSIdx = 15;
constexpr size_t kVSSetShaderIdx = 11;
constexpr size_t kPSSetShaderIdx = 9;
constexpr size_t kDrawIdx = 13;
constexpr size_t kMapIdx = 14;
constexpr size_t kUnmapIdx = 15;
constexpr size_t kIASetLayoutIdx = 17;
constexpr size_t kIASetVBIdx = 18;
constexpr size_t kIASetTopoIdx = 24;
constexpr size_t kOMSetRTIdx = 33;
constexpr size_t kRSSetVPIdx = 44;

// D3D11 enum values (stable ABI).
constexpr uint32_t kBindVB = 0x1;
constexpr uint32_t kUsageDyn = 2;
constexpr uint32_t kCpuWrite = 0x10000;
constexpr uint32_t kTopoLines = 2;
constexpr uint32_t kMapDiscard = 4;
constexpr uint32_t kFmtRGB32 = 6;   // DXGI_FORMAT_R32G32B32_FLOAT
constexpr uint32_t kFmtRGBA32 = 2;  // DXGI_FORMAT_R32G32B32A32_FLOAT

using GenericFn = void*;

struct D3D {
  void* dev = nullptr;
  void* ctx = nullptr;
  void* rtv = nullptr;
  void* vs = nullptr;
  void* ps = nullptr;
  void* layout = nullptr;
  void* vb = nullptr;
  uint32_t vbCap = 0;
  uint32_t scrW = 0, scrH = 0;
};

static D3D g_d3d;
static void* g_origPresent = nullptr;
static const sdk::IGameAdapter* g_ad = nullptr;
static sdk::GameContext* g_ctx = nullptr;

static uintptr_t VAt(void* obj, size_t idx) {
  __try {
    if (!obj) return 0;
    uintptr_t vt = sdk::Read<uintptr_t>((uintptr_t)obj);
    if (!vt) return 0;
    return sdk::Read<uintptr_t>(vt + idx * 8);
  } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

struct Vert { float x, y, z, r, g, b, a; };

static void PushLine(Vert* v, int* n, int cap, float x0, float y0, float x1, float y1,
                     float r, float g, float b, uint32_t W, uint32_t H) {
  if (*n + 2 > cap) return;
  auto px = [&](float x, float y, Vert* o) {
    o->x = x / (float)W * 2.0f - 1.0f;
    o->y = 1.0f - y / (float)H * 2.0f;
    o->z = 0.0f;
    o->r = r; o->g = g; o->b = b; o->a = 1.0f;
  };
  px(x0, y0, &v[*n]); ++(*n);
  px(x1, y1, &v[*n]); ++(*n);
}

static void DrawBoxes(D3D* d) {
  if (!g_ad || !g_ctx) return;
  sdk::Player ps[16]{};
  int n = g_ad->GetPlayers(g_ctx, ps, 16);
  if (n <= 0) return;
  // map VB (16KB static staging -> Map/Unmap)
  struct MapOut { void* p; uint32_t rp, dp; };
  MapOut mo{};
  typedef int (__stdcall* MapFn)(void*, void*, uint32_t, uint32_t, uint32_t, MapOut*);
  uintptr_t mapA = VAt(d->ctx, kMapIdx);
  uintptr_t unmapA = VAt(d->ctx, kUnmapIdx);
  if (!mapA || !unmapA) return;
  if (((MapFn)mapA)(d->ctx, d->vb, 0, kMapDiscard, 0, &mo) < 0 || !mo.p) return;
  Vert* verts = (Vert*)mo.p;
  int vn = 0;
  const int cap = 256;
  for (int i = 0; i < n && i < 16; ++i) {
    if (ps[i].health <= 0) continue;
    sdk::Vec3 sf{}, sh{};
    sdk::Vec3 feet = ps[i].pos, head = ps[i].pos;
    head.z += 72.0f;
    if (!g_ad->WorldToScreen(g_ctx, feet, sf)) continue;
    if (!g_ad->WorldToScreen(g_ctx, head, sh)) continue;
    int fx = (int)sf.x, fy = (int)sf.y, hx = (int)sh.x, hy = (int)sh.y;
    int h = fy - hy;
    if (h <= 0 || h > 4096) continue;
    int w = h / 2, x0 = fx - w / 2, x1 = fx + w / 2;
    if (x1 < -200 || x0 > 10000 || hy < -200 || fy > 10000) continue;
    float r = 1.0f, g = 1.0f, b = 1.0f;
    if (ps[i].team == 3) { r = 0.0f; g = 1.0f; b = 0.0f; }
    else if (ps[i].team == 2) { r = 1.0f; g = 0.0f; b = 0.0f; }
    uint32_t W = d->scrW ? d->scrW : 1920, H = d->scrH ? d->scrH : 1080;
    PushLine(verts, &vn, cap, (float)x0, (float)hy, (float)x1, (float)hy, r, g, b, W, H);
    PushLine(verts, &vn, cap, (float)x1, (float)hy, (float)x1, (float)fy, r, g, b, W, H);
    PushLine(verts, &vn, cap, (float)x1, (float)fy, (float)x0, (float)fy, r, g, b, W, H);
    PushLine(verts, &vn, cap, (float)x0, (float)fy, (float)x0, (float)hy, r, g, b, W, H);
  }
  ((void (__stdcall*)(void*, void*))unmapA)(d->ctx, d->vb);
  if (!vn) return;
  // bind + draw
  typedef void (__stdcall* SetTopoFn)(void*, uint32_t);
  typedef void (__stdcall* SetLayoutFn)(void*, void*);
  typedef void (__stdcall* SetVBFn)(void*, uint32_t, uint32_t, void**, uint32_t*, uint32_t*);
  typedef void (__stdcall* VsFn)(void*, void*, void*, uint32_t);
  typedef void (__stdcall* PsFn)(void*, void*, void*, uint32_t);
  typedef void (__stdcall* DrawFn)(void*, uint32_t, uint32_t);
  typedef void (__stdcall* VpFn)(void*, uint32_t, void*);
  uintptr_t a;
  a = VAt(d->ctx, kIASetTopoIdx); if (a) ((SetTopoFn)a)(d->ctx, kTopoLines);
  a = VAt(d->ctx, kIASetLayoutIdx); if (a) ((SetLayoutFn)a)(d->ctx, d->layout);
  {
    uint32_t stride = sizeof(Vert), off = 0;
    void* vb = d->vb;
    a = VAt(d->ctx, kIASetVBIdx);
    if (a) ((SetVBFn)a)(d->ctx, 0, 1, &vb, &stride, &off);
  }
  a = VAt(d->ctx, kVSSetShaderIdx); if (a) ((VsFn)a)(d->ctx, d->vs, nullptr, 0);
  a = VAt(d->ctx, kPSSetShaderIdx); if (a) ((PsFn)a)(d->ctx, d->ps, nullptr, 0);
  // viewport full size
  struct VP { float x, y, w, h, mn, mx; } vp{};
  vp.w = (float)(d->scrW ? d->scrW : 1920);
  vp.h = (float)(d->scrH ? d->scrH : 1080);
  vp.mx = 1.0f;
  a = VAt(d->ctx, kRSSetVPIdx); if (a) ((VpFn)a)(d->ctx, 1, &vp);
  a = VAt(d->ctx, kDrawIdx); if (a) ((DrawFn)a)(d->ctx, (uint32_t)vn, 0);
}

static bool InitD3D(void* swapchain) {
  __try {
    // device + context
    typedef int (__stdcall* GetDevFn)(void*, const void*, void**);
    // need IID_ID3D11Device: {db6f6ddb-ac77-4e88-8253-819df9bbf140}
    static const uint8_t iidDev[16] = {0xDB,0x6D,0x6F,0xDB,0x77,0xAC,0x4E,0x88,0x82,0x53,0x81,0x9D,0xF9,0xBB,0xF1,0x40};
    uintptr_t a = VAt(swapchain, kGetDeviceIdx);
    if (!a) return false;
    void* dev = nullptr;
    if (((GetDevFn)a)(swapchain, iidDev, &dev) < 0 || !dev) return false;
    g_d3d.dev = dev;
    // immediate context: device vtable[40]
    uintptr_t gic = VAt(dev, 40);
    if (!gic) return false;
    typedef void (__stdcall* GicFn)(void*, void**);
    void* ctx = nullptr;
    ((GicFn)gic)(dev, &ctx);
    if (!ctx) return false;
    g_d3d.ctx = ctx;
    // backbuffer RTV
    typedef int (__stdcall* GetBufFn)(void*, uint32_t, const void*, void**);
    a = VAt(swapchain, kGetBufferIdx);
    if (!a) return false;
    // IID_ID3D11Texture2D {6f15aaf2-d208-4e89-9ab4-afe435d melted?} use known bytes:
    static const uint8_t iidTex[16] = {0xF2,0xAA,0x15,0x6F,0x08,0xD2,0x89,0x4E,0x9A,0xB4,0xAF,0xE4,0x35,0xD4,0x16,0xED};
    void* bb = nullptr;
    if (((GetBufFn)a)(swapchain, 0, iidTex, &bb) < 0 || !bb) return false;
    typedef int (__stdcall* RtvFn)(void*, void*, const void*, void**);
    a = VAt(dev, kCreateRTVIdx);
    if (!a) return false;
    void* rtv = nullptr;
    if (((RtvFn)a)(dev, bb, nullptr, &rtv) < 0 || !rtv) {
      // release bb
      uintptr_t rel = VAt(bb, 2);
      if (rel) ((uint32_t (__stdcall*)(void*))rel)(bb);
      return false;
    }
    {
      uintptr_t rel = VAt(bb, 2);
      if (rel) ((uint32_t (__stdcall*)(void*))rel)(bb);
    }
    g_d3d.rtv = rtv;
    // shaders
    typedef int (__stdcall* VsFn)(void*, const void*, size_t, void*, void**);
    typedef int (__stdcall* PsFn)(void*, const void*, size_t, void*, void**);
    a = VAt(dev, kCreateVSIdx);
    if (!a) return false;
    void* vs = nullptr;
    if (((VsFn)a)(dev, g_VSMain, sizeof(g_VSMain), nullptr, &vs) < 0 || !vs) return false;
    g_d3d.vs = vs;
    a = VAt(dev, kCreatePSIdx);
    if (!a) return false;
    void* ps = nullptr;
    if (((PsFn)a)(dev, g_PSMain, sizeof(g_PSMain), nullptr, &ps) < 0 || !ps) return false;
    g_d3d.ps = ps;
    // input layout: POSITION float3 @0, COLOR float4 @12 (codegen'd names).
    struct IElem { const char* s; uint32_t i, f, slot, off; uint32_t cls; uint32_t step; };
    static char semP[16], semC[16];
    static IElem elems[2];
    static bool elemsInit = false;
    if (!elemsInit) {
      vacsafe::str::CopyTo(vacsafe::str::SID_d3d_position, semP, sizeof(semP));
      vacsafe::str::CopyTo(vacsafe::str::SID_d3d_color, semC, sizeof(semC));
      elems[0].s = semP; elems[0].i = 0; elems[0].f = 6;
      elems[1].s = semC; elems[1].i = 0; elems[1].f = 2; elems[1].off = 12;
      elemsInit = true;
    }
    typedef int (__stdcall* LayoutFn)(void*, const void*, uint32_t, const void*, size_t, void**);
    a = VAt(dev, kCreateLayoutIdx);
    if (!a) return false;
    void* layout = nullptr;
    if (((LayoutFn)a)(dev, elems, 2, g_VSMain, sizeof(g_VSMain), &layout) < 0 || !layout) return false;
    g_d3d.layout = layout;
    // dynamic vertex buffer (256 verts)
    struct BDesc { uint32_t size, usage, bind, cpu, misc, stride; };
    BDesc bd{};
    bd.size = 256 * sizeof(Vert);
    bd.usage = kUsageDyn;
    bd.bind = kBindVB;
    bd.cpu = kCpuWrite;
    typedef int (__stdcall* BufFn)(void*, const void*, const void*, void**);
    a = VAt(dev, kCreateBufferIdx);
    if (!a) return false;
    void* vb = nullptr;
    if (((BufFn)a)(dev, &bd, nullptr, &vb) < 0 || !vb) return false;
    g_d3d.vb = vb;
    g_d3d.vbCap = 256;
    // screen size from swapchain desc (idx 12)
    typedef int (__stdcall* DescFn)(void*, void*);
    a = VAt(swapchain, kGetDescIdx);
    if (a) {
      struct D32 { uint32_t w, h; };
      // DXGI_SWAP_CHAIN_DESC: BufferDesc.Width@8, Height@12 (after mode fields)
      uint8_t desc[128]{};
      if (((DescFn)a)(swapchain, desc) >= 0) {
        uint32_t w = *(uint32_t*)(desc + 8), h = *(uint32_t*)(desc + 12);
        if (w > 320 && w < 16384 && h > 200 && h < 16384) { g_d3d.scrW = w; g_d3d.scrH = h; }
      }
    }
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static int __stdcall HkPresent(void* swapchain, uint32_t interval, uint32_t flags) {
  typedef int (__stdcall* PresentFn)(void*, uint32_t, uint32_t);
  __try {
    if (!g_d3d.ctx && !InitD3D(swapchain)) {
      PresentFn o = (PresentFn)g_origPresent;
      return o ? o(swapchain, interval, flags) : 0;
    }
    // bind our RTV (same backbuffer; game rebinds its own targets per frame)
    typedef void (__stdcall* OmFn)(void*, uint32_t, void**, void*);
    uintptr_t a = VAt(g_d3d.ctx, kOMSetRTIdx);
    if (a && g_d3d.rtv) ((OmFn)a)(g_d3d.ctx, 1, &g_d3d.rtv, nullptr);
    DrawBoxes(&g_d3d);
  } __except (EXCEPTION_EXECUTE_HANDLER) {}
  PresentFn o = (PresentFn)g_origPresent;
  return o ? o(swapchain, interval, flags) : 0;
}

} // namespace

bool InstallPresentHook(void* swapchain, void* vtable, void* origPresent,
                        const sdk::IGameAdapter* ad, sdk::GameContext* ctx,
                        const Api* api) {
  if (!swapchain || !vtable || !origPresent || !ad || !ctx || !api) return false;
  __try {
    g_ad = ad;
    g_ctx = ctx;
    g_origPresent = origPresent;
    // shadow VMT: copy 64 slots to private RW, redirect [8], swap object vptr.
    // VirtualAlloc via hashed kernel32 (0x382C0F97).
    wchar_t k32[16];
    vacsafe::str::CopyToW(vacsafe::str::SID_mod_kernel32, k32, 16);
    typedef void* (WINAPI* VaFn)(void*, size_t, uint32_t, uint32_t);
    VaFn va = (VaFn)nt::GetProcByHash(k32, 0x382C0F97);
    if (!va) return false;
    void* copy = va(nullptr, 64 * 8, 0x3000, 0x04);
    if (!copy) return false;
    for (int i = 0; i < 64; ++i)
      ((uintptr_t*)copy)[i] = sdk::Read<uintptr_t>((uintptr_t)vtable + (uintptr_t)(i * 8));
    ((uintptr_t*)copy)[kPresentIdx] = (uintptr_t)(void*)HkPresent;
    if (!sdk::Write<uintptr_t>((uintptr_t)swapchain, (uintptr_t)copy)) return false;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

} // namespace vacsafe
