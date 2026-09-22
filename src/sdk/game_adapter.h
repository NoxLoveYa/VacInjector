#pragma once
#include <windows.h>
#include <cstdint>
// Universal game-agnostic SDK surface (Phase 05).
// HARD CONSTRAINT: everything here runs on the payload raw-DllMain path
// (CRT startup bypassed) -> NO STL, NO CRT calls, NO exceptions, NO RTTI,
// no static initializers. Fixed-size buffers, SEH-guarded reads, kernel32 only.
namespace vacsafe::sdk {

constexpr int kMaxPlayers = 64;
constexpr int kMaxNameLen = 32;
constexpr int kMaxExeLen = 64;
constexpr int kMaxErrLen = 160;

struct Vec3 { float x, y, z; };
struct Vec4 { float x, y, z, w; };

struct Player {
  Vec3 pos{};
  int health = 0;
  int team = 0;
  bool dormant = true;
  char name[kMaxNameLen]{};
};

struct GameModules {
  uintptr_t clientBase = 0;
  size_t clientSize = 0;
  uintptr_t engineBase = 0;
  size_t engineSize = 0;
  uintptr_t schemaBase = 0; // schemasystem.dll (Source2) or 0
  size_t schemaSize = 0;
};

struct GameContext {
  uint32_t pid = 0;
  char exeName[kMaxExeLen]{};
  GameModules mod;
  // Resolved globals (absolute addresses), 0 = unresolved:
  uintptr_t entityList = 0;
  uintptr_t localPlayer = 0;
  uintptr_t viewMatrix = 0;
  // Adapter scratch (offsets, flags). CS2: [0]=offHealth [1]=offTeam
  // [2]=offSceneNode [3]=offOrigin [4]=schemaOk [5]=lastStage [6]=mapInstCount
  // [7]=hostApi [8]=mzWord [9]=textLo32 [10]=textHi32 [12]=readDiag [13]=chunk0
  // [14]=offPawn.
  uintptr_t priv[16]{};
  char err[kMaxErrLen]{};
};

// Pure-C adapter table (NOT C++ virtuals): constant-initialized, zero dynamic
// init, raw-DllMain safe. One const instance per game (see payload/adapters/).
struct IGameAdapter {
  const char* (*Name)();
  bool (*Init)(GameContext* ctx);
  int (*GetPlayers)(GameContext* ctx, Player* out, int max);
  bool (*WorldToScreen)(GameContext* ctx, const Vec3& w, Vec3& s);
};

// --- memory (SEH-guarded + VirtualQuery-gated: NEVER fault in target) ---
// Rationale (2026-09-21): hundreds of caught AVs in a tight loop trip CS2's
// exception monitor (fastfail). Every read first validates the page via
// VirtualQuery (hashed, cached); __try remains as belt-and-braces only.
typedef SIZE_T (WINAPI* VirtualQueryFn)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
void* SdkResolveVQ(); // sdk.cpp: hashed VirtualQuery address (CRT-free)
// Raw VirtualQuery for region walks (swap RefSearch etc.). Returns bytes written.
SIZE_T QueryMem(uintptr_t addr, void* mbi, size_t cap);
inline bool CanRead(uintptr_t addr, size_t n) {
  static void* cachedVQ = nullptr;
  if (!cachedVQ) {
    cachedVQ = SdkResolveVQ();
    if (!cachedVQ) return false;
  }
  // All bytes must lie in committed, readable, non-guard pages.
  uintptr_t first = addr & ~(uintptr_t)0xFFF;
  uintptr_t last = (addr + n - 1) & ~(uintptr_t)0xFFF;
  for (uintptr_t pg = first;; pg += 0x1000) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!((VirtualQueryFn)cachedVQ)((LPCVOID)pg, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & PAGE_GUARD) return false;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                          PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
      return false;
    if (pg == last) break;
  }
  return true;
}

template <typename T>
inline T Read(uintptr_t addr) {
  T z{};
  if (!addr || !CanRead(addr, sizeof(T))) return z;
  __try {
    return *(volatile T*)addr;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return z; }
}

template <typename T>
inline bool Write(uintptr_t addr, const T& v) {
  if (!addr || !CanRead(addr, sizeof(T))) return false;
  __try {
    *(volatile T*)addr = v;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

inline bool ReadBuf(uintptr_t addr, void* out, size_t n) {
  if (!addr || !out || !n || !CanRead(addr, n)) return false;
  __try {
    const volatile uint8_t* s = (const volatile uint8_t*)addr;
    uint8_t* d = (uint8_t*)out;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// --- sdk.cpp: module fill, pattern scan, RIP resolve, W2S, tiny utils ---
bool FillModules(GameContext* ctx); // client/engine/schemasystem via nt::GetModuleBase
// Pattern with explicit length; mask[i]=='?' means wildcard. Returns absolute match or 0.
uintptr_t PatternScan(uintptr_t base, size_t size, const uint8_t* pat, const char* mask, size_t len);
// Resolve RIP-relative DWORD at [match+dispOff], insn length instrLen.
uintptr_t ResolveRip(uintptr_t match, size_t instrLen, size_t dispOff);
// err helpers (no CRT): copy + u32->dec/hex into fixed buffers.
void SetErr(GameContext* ctx, const char* msg);
void U32ToDec(char* out, size_t cap, uint32_t v);
void U64ToHex(char* out, size_t cap, uint64_t v);
size_t StrLen(const char* s, size_t cap);
bool StrEqI(const char* a, const char* b);

} // namespace vacsafe::sdk
