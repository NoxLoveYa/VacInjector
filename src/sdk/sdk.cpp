#include "game_adapter.h"
#include "nt_api.h"
#include "peb.h"

// SDK core: module fill, pattern scan, RIP resolve, W2S math, tiny utils.
// CRT-free TU (raw-DllMain safe): no printf/malloc/new, manual loops only.
namespace vacsafe::sdk {

size_t StrLen(const char* s, size_t cap) {
  size_t n = 0;
  if (!s) return 0;
  while (n < cap && s[n]) ++n;
  return n;
}

bool StrEqI(const char* a, const char* b) {
  if (!a || !b) return false;
  size_t i = 0;
  for (;; ++i) {
    char ca = a[i], cb = b[i];
    if (ca >= 'A' && ca <= 'Z') ca += 32;
    if (cb >= 'A' && cb <= 'Z') cb += 32;
    if (!ca && !cb) return true;
    if (!ca || !cb || ca != cb) return false;
    if (i > 128) return false;
  }
}

void SetErr(GameContext* ctx, const char* msg) {
  if (!ctx || !msg) return;
  size_t i = 0;
  for (; i + 1 < kMaxErrLen && msg[i]; ++i) ctx->err[i] = msg[i];
  ctx->err[i] = 0;
}

void U32ToDec(char* out, size_t cap, uint32_t v) {
  if (!out || cap < 2) return;
  char tmp[12]; int n = 0;
  if (!v) tmp[n++] = '0';
  while (v && n < 11) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
  size_t i = 0;
  while (n > 0 && i + 1 < cap) out[i++] = tmp[--n];
  out[i] = 0;
}

void U64ToHex(char* out, size_t cap, uint64_t v) {
  static const char* digits = "0123456789ABCDEF";
  if (!out || cap < 3) return;
  out[0] = '0'; out[1] = 'x';
  size_t i = 2;
  bool started = false;
  for (int sh = 60; sh >= 0; sh -= 4) {
    int d = (int)((v >> sh) & 0xF);
    if (d || started || sh == 0) { started = true; if (i + 1 < cap) out[i++] = digits[d]; }
  }
  out[i] = 0;
}

// Module code size: headers SizeOfImage (guarded; 0 on failure).
static size_t ModuleSize(void* base) {
  __try {
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD sz = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        ? ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SizeOfImage
        : ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SizeOfImage;
    return (sz && sz < 0x40000000) ? sz : 0;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

bool FillModules(GameContext* ctx) {
  if (!ctx) return false;
  // Wide literals for universal modules: every process links these (zero signal).
  void* client = nt::GetModuleBase(L"client.dll");
  void* engine2 = nt::GetModuleBase(L"engine2.dll");
  void* engine = engine2 ? engine2 : nt::GetModuleBase(L"engine.dll");
  void* schema = nt::GetModuleBase(L"schemasystem.dll");
  if (!client) { SetErr(ctx, "client.dll not loaded (wrong game?)"); return false; }
  ctx->mod.clientBase = (uintptr_t)client;
  ctx->mod.clientSize = ModuleSize(client);
  if (engine) { ctx->mod.engineBase = (uintptr_t)engine; ctx->mod.engineSize = ModuleSize(engine); }
  if (schema) { ctx->mod.schemaBase = (uintptr_t)schema; ctx->mod.schemaSize = ModuleSize(schema); }
  if (!ctx->mod.clientSize) { SetErr(ctx, "client.dll headers unreadable"); return false; }
  return true;
}

uintptr_t PatternScan(uintptr_t base, size_t size, const uint8_t* pat, const char* mask, size_t len) {
  if (!base || !size || !pat || !mask || !len || len > 64) return 0;
  // Page-resilient: a single __try around the whole range aborts on the first
  // unreadable page (discarded .reloc, guard pages) and reports false negatives.
  // Walk page by page (4K), skipping faulting pages, overlapping by len.
  const size_t kPage = 0x1000;
  for (size_t page = 0; page < size; page += kPage) {
    size_t chunkEnd = page + kPage + len;
    if (chunkEnd > size) chunkEnd = size;
    __try {
      for (size_t i = page; i + len <= chunkEnd; ++i) {
        const volatile uint8_t* p = (const volatile uint8_t*)(base + i);
        size_t j = 0;
        for (; j < len; ++j) {
          if (mask[j] && p[j] != pat[j]) break;
        }
        if (j == len) return base + i;
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
  }
  return 0;
}

uintptr_t ResolveRip(uintptr_t match, size_t instrLen, size_t dispOff) {
  if (!match) return 0;
  __try {
    int32_t disp = *(volatile int32_t*)(match + dispOff);
    return match + instrLen + (int64_t)disp;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

} // namespace vacsafe::sdk
