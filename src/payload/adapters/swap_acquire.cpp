#include "swap_hook.h"
#include "game_adapter.h"
#include "nt_api.h"
#include "strings.inc"
#include <windows.h>
#include <winternl.h>
#include <d3d11.h>
#include <dxgi.h>

// Swapchain acquisition for the Present hook. All hashed, CRT-free, guarded.
namespace vacsafe {
namespace {

typedef void* (WINAPI* GetModFn)(const wchar_t*);
typedef void* (WINAPI* RegClsFn)(const void*);
typedef void* (WINAPI* CreateWinFn)(uint32_t, const char*, const char*, uint32_t, int, int, int, int, void*, void*, void*, void*);
typedef int (WINAPI* DestroyWinFn)(void*);
typedef void* (WINAPI* VirtAllocFn)(void*, size_t, uint32_t, uint32_t);
typedef HRESULT (WINAPI* CreateDevFn)(void*, int, void*, uint32_t, const void*, uint32_t, uint32_t, const void*, void**, void**, void*, void**);
typedef intptr_t (__stdcall* WndProcFn)(void*, uint32_t, uintptr_t, intptr_t);

static intptr_t __stdcall DummyWndProc(void* h, uint32_t m, uintptr_t w, intptr_t l) {
  static void* defWnd = nullptr;
  if (!defWnd) {
    wchar_t u32[16];
    vacsafe::str::CopyToW(vacsafe::str::SID_mod_user32, u32, 16);
    defWnd = nt::GetProcByHash(u32, 0x68F05E41); // DefWindowProcA
  }
  if (!defWnd) return 0;
  return ((intptr_t (__stdcall*)(void*, uint32_t, uintptr_t, intptr_t))defWnd)(h, m, w, l);
}

struct Resolved {
  GetModFn getMod = nullptr;
  RegClsFn regCls = nullptr;
  CreateWinFn createWin = nullptr;
  DestroyWinFn destroyWin = nullptr;
  VirtAllocFn virtAlloc = nullptr;
  CreateDevFn createDev = nullptr;
  bool ok = false;
};

static bool ResolveAll(Resolved* r) {
  __try {
    wchar_t k32[16], u32[16], d3d[16];
    vacsafe::str::CopyToW(vacsafe::str::SID_mod_kernel32, k32, 16);
    vacsafe::str::CopyToW(vacsafe::str::SID_mod_user32, u32, 16);
    vacsafe::str::CopyToW(vacsafe::str::SID_mod_d3d11, d3d, 16);
    r->getMod = (GetModFn)nt::GetProcByHash(k32, 0x5A153F58); // GetModuleHandleA
    if (!r->getMod) return false;
    r->regCls = (RegClsFn)nt::GetProcByHash(u32, 0x7715AB81); // RegisterClassA
    r->createWin = (CreateWinFn)nt::GetProcByHash(u32, 0x1C82E26F); // CreateWindowExA
    r->destroyWin = (DestroyWinFn)nt::GetProcByHash(u32, 0x14841E87); // DestroyWindow
    r->virtAlloc = (VirtAllocFn)nt::GetProcByHash(k32, 0x382C0F97); // VirtualAlloc
    void* d3d11 = nt::GetModuleBase(d3d);
    if (!d3d11) return false; // not a D3D11 process (Vulkan?) -> fail closed
    char dc[48];
    vacsafe::str::CopyTo(vacsafe::str::SID_api_d3dcreate, dc, sizeof(dc));
    r->createDev = (CreateDevFn)nt::GetProcByName(d3d11, dc);
    r->ok = r->regCls && r->createWin && r->destroyWin && r->virtAlloc && r->createDev;
    return r->ok;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

} // namespace

bool AcquireSwapchain(SwapHit* out) {
  if (!out) return false;
  *out = SwapHit{};
  __try {
    Resolved r{};
    if (!ResolveAll(&r)) return false;

    // hidden 1x1 window (transient: destroyed after acquisition)
    char cls[16];
    vacsafe::str::CopyTo(vacsafe::str::SID_wnd_cls, cls, sizeof(cls));
    struct WndA {
      uint32_t style;
      void* lpfnWndProc;
      int cbClsExtra, cbWndExtra;
      void* hInstance;
      void* hIcon;
      void* hCursor;
      void* hbrBackground;
      const char* lpszMenuName;
      const char* lpszClassName;
    } wc{};
    wc.lpfnWndProc = (void*)DummyWndProc;
    wc.hInstance = r.getMod(nullptr);
    wc.lpszClassName = cls;
    if (!r.regCls(&wc)) return false;
    void* hwnd = r.createWin(0, cls, cls, 0x80000000u /*WS_POPUP*/, 0, 0, 1, 1,
                             nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) return false;

    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 1;
    sd.BufferDesc.Width = 1;
    sd.BufferDesc.Height = 1;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = (HWND)hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    void* sc = nullptr;
    void* dev = nullptr;
    void* ctx = nullptr;
    D3D_FEATURE_LEVEL fl = D3D_FEATURE_LEVEL_11_0;
    HRESULT hr = r.createDev(nullptr, 1 /*HARDWARE*/, nullptr, 0, &fl, 1,
                             D3D11_SDK_VERSION, &sd, &sc, &dev, nullptr, &ctx);
    // release ours immediately except the vtable address
    uintptr_t vtable = 0;
    if (hr >= 0 && sc) {
      vtable = sdk::Read<uintptr_t>((uintptr_t)sc);
      // release dummy COM objects via vtables (Release idx 2)
      typedef uint32_t (__stdcall* RelFn)(void*);
      auto rel = [&](void* o) {
        __try {
          uintptr_t* vt = (uintptr_t*)sdk::Read<uintptr_t>((uintptr_t)o);
          if (vt) ((RelFn)vt[2])(o);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
      };
      rel(sc); rel(dev); rel(ctx);
    }
    r.destroyWin(hwnd);
    if (!vtable) return false;

    // dxgi range for validation
    wchar_t dg[16];
    vacsafe::str::CopyToW(vacsafe::str::SID_mod_dxgi, dg, 16);
    void* dxgi = nt::GetModuleBase(dg);
    if (!dxgi) return false;
    // module size via headers (guarded)
    size_t dxgiSize = 0;
    {
      auto* dos = (IMAGE_DOS_HEADER*)dxgi;
      if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)dxgi + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE)
          dxgiSize = nt->OptionalHeader.SizeOfImage;
      }
    }
    if (!dxgiSize || dxgiSize > 0x4000000) return false;

    // RefSearch: committed private RW heap for pointers to vtable (cap ~768MB).
    uintptr_t addr = 0x10000;
    size_t scanned = 0;
    int hits = 0;
    void* best = nullptr;
    while (scanned < (768u * 1024u * 1024u)) {
      MEMORY_BASIC_INFORMATION mbi{};
      SIZE_T q = sdk::QueryMem(addr, &mbi, sizeof(mbi));
      if (!q) break;
      uintptr_t end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
      if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
          (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) {
        size_t n = mbi.RegionSize;
        if (scanned + n > (768u * 1024u * 1024u)) n = (768u * 1024u * 1024u) - scanned;
        for (size_t off = 0; off + 8 <= n; off += 8) {
          uintptr_t v = sdk::Read<uintptr_t>((uintptr_t)mbi.BaseAddress + off);
          if (v == vtable) {
            // candidate object: verify Present slot lives in dxgi
            uintptr_t p8 = sdk::Read<uintptr_t>(vtable + 8 * 8);
            if (p8 >= (uintptr_t)dxgi && p8 < (uintptr_t)dxgi + dxgiSize) {
              ++hits;
              if (!best) best = (void*)((uintptr_t)mbi.BaseAddress + off);
              if (hits >= 8) break;
            }
          }
        }
        scanned += n;
      }
      if (end <= addr) break;
      addr = end;
      if (hits >= 8) break;
    }
    if (!best || !hits) return false;
    out->swapchain = best;
    out->vtable = (void*)vtable;
    out->present = (void*)sdk::Read<uintptr_t>(vtable + 8 * 8);
    out->scannedMB = (int)(scanned >> 20);
    out->hits = hits;
    return out->present != nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

} // namespace vacsafe
