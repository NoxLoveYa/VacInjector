#include "stealth.h"
#include "peb.h"
#include <windows.h>
#include <winternl.h>
#include <cstddef>

// Phase 04 stealth core. CONSTRAINT: this TU is linked into the payload and runs on the
// raw-DllMain path (CRT startup bypassed) -> kernel32/ntdll + compiler intrinsics ONLY.
// No CRT (no printf/malloc/new/exceptions), no C++ static initializers in this TU.
// Sensitive NT APIs resolve via embedded hash resolver: ZERO new IAT entries.

namespace vacsafe::stealth {

void Wipe(void* p, size_t n) { SecureZeroMemory(p, n); }

// ---- compile-time djb2 (matches nt::HashName in common) ----
static constexpr uint32_t Djb2(const char* s) {
  uint32_t h = 5381;
  while (*s) h = ((h << 5) + h + (uint8_t)*s++);
  return h;
}
static constexpr uint32_t kNtSetInfoThreadHash = Djb2("NtSetInformationThread");
static constexpr uint32_t kNtProtectMemHash = Djb2("NtProtectVirtualMemory");

using peb::LdrData;
using peb::LdrEntry;

using NtSetInformationThreadFn = LONG (NTAPI*)(HANDLE, ULONG /*THREADINFOCLASS*/, void*, ULONG);
using NtProtectVirtualMemoryFn = LONG (NTAPI*)(HANDLE, void**, SIZE_T*, ULONG, ULONG*);

static HMODULE FindModuleByName(const wchar_t* name /*lowercase, e.g. L"ntdll.dll"*/) {
  PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
  if (!peb || !peb->Ldr) return nullptr;
  auto* ldr = (LdrData*)peb->Ldr;
  LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
  for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
    auto* e = (LdrEntry*)((uint8_t*)cur - offsetof(LdrEntry, InMemoryOrderLinks));
    const wchar_t* a = e->BaseDllName.Buffer;
    const wchar_t* b = name;
    if (!a || !b) continue;
    USHORT i = 0;
    for (; ; ++i) {
      wchar_t ca = a[i], cb = b[i];
      if (ca >= L'A' && ca <= L'Z') ca += 32;
      if (!cb && !ca) return (HMODULE)e->DllBase; // full match
      if (!cb || !ca || ca != cb) break;
      if (i > 64) break;
    }
  }
  return nullptr;
}

static void* GetProcByHash(HMODULE mod, uint32_t hash) {
  if (!mod) return nullptr;
  auto* dos = (IMAGE_DOS_HEADER*)mod;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
  auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)mod + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
  if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return nullptr;
  auto& exp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!exp.VirtualAddress) return nullptr;
  auto* dir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)mod + exp.VirtualAddress);
  auto* names = (DWORD*)((uint8_t*)mod + dir->AddressOfNames);
  auto* ords = (WORD*)((uint8_t*)mod + dir->AddressOfNameOrdinals);
  auto* funcs = (DWORD*)((uint8_t*)mod + dir->AddressOfFunctions);
  for (DWORD i = 0; i < dir->NumberOfNames; ++i) {
    const char* nm = (const char*)((uint8_t*)mod + names[i]);
    if (Djb2(nm) != hash) continue;
    WORD ord = ords[i];
    if ((DWORD)ord >= dir->NumberOfFunctions) return nullptr;
    DWORD rva = funcs[ord];
    if (rva >= exp.VirtualAddress && rva < exp.VirtualAddress + exp.Size) return nullptr; // forwarded
    return (uint8_t*)mod + rva;
  }
  return nullptr;
}

static HMODULE NtModule() {
  static HMODULE cached = nullptr;
  if (!cached) cached = FindModuleByName(L"ntdll.dll");
  return cached;
}

// ---- header erase: zero DOS + NT + section headers (SizeOfHeaders bytes) ----
static uint32_t EraseHeaders(void* base) {
  if (!base) return 0;
  __try {
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD hdrSize = 0;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      hdrSize = nt->OptionalHeader.SizeOfHeaders;
    else
      hdrSize = ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SizeOfHeaders;
    if (!hdrSize || hdrSize > 0x10000) return 0;
    auto prot = (NtProtectVirtualMemoryFn)GetProcByHash(NtModule(), kNtProtectMemHash);
    if (!prot) return 0;
    void* addr = base;
    SIZE_T size = hdrSize;
    ULONG old = 0;
    if (prot((HANDLE)(LONG_PTR)-1, &addr, &size, PAGE_READWRITE, &old) != 0) return 0;
    SecureZeroMemory(base, hdrSize);
    ULONG old2 = 0;
    prot((HANDLE)(LONG_PTR)-1, &addr, &size, PAGE_READONLY, &old2);
    return kEraseHeaders;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// ---- LDR unlink verify: manual-mapped images are absent by construction.
// If present (LoadLibrary-fallback image), detach from all three orders. ----
static uint32_t UnlinkLdr(void* base) {
  if (!base) return 0;
  __try {
    PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb || !peb->Ldr) return kUnlinkLdr; // no LDR access: assume manual-mapped clean
    bool found = false;
    auto* ldr = (LdrData*)peb->Ldr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
      auto* e = CONTAINING_RECORD(cur, LdrEntry, InLoadOrderLinks);
      if (e->DllBase != base) continue;
      found = true;
      e->InLoadOrderLinks.Blink->Flink = e->InLoadOrderLinks.Flink;
      e->InLoadOrderLinks.Flink->Blink = e->InLoadOrderLinks.Blink;
      e->InMemoryOrderLinks.Blink->Flink = e->InMemoryOrderLinks.Flink;
      e->InMemoryOrderLinks.Flink->Blink = e->InMemoryOrderLinks.Blink;
      if (e->InInitOrderLinks.Flink && e->InInitOrderLinks.Blink) {
        e->InInitOrderLinks.Blink->Flink = e->InInitOrderLinks.Flink;
        e->InInitOrderLinks.Flink->Blink = e->InInitOrderLinks.Blink;
      }
      break;
    }
    (void)found;
    return kUnlinkLdr; // absent-by-construction or detached: state achieved
  } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// ---- per-thread hiding (Phase 05 payload threads call at thread start) ----
static NtSetInformationThreadFn ResolveNtSetInfo() {
  return (NtSetInformationThreadFn)GetProcByHash(NtModule(), kNtSetInfoThreadHash);
}

[[maybe_unused]] static uint32_t HideCurrentThread() {
  auto fn = ResolveNtSetInfo();
  if (!fn) return 0;
  // ThreadHideFromDebugger = 17; pseudo-handle needs no import.
  if (fn((HANDLE)(LONG_PTR)-2, 17, nullptr, 0) != 0) return 0;
  return kHideThread;
}

[[maybe_unused]] static uint32_t SpoofThreadStart(HANDLE hThread, void* fakeStart) {
  auto fn = ResolveNtSetInfo();
  if (!fn || !fakeStart) return 0;
  // ThreadQuerySetWin32StartAddress = 9
  if (fn(hThread, 9, &fakeStart, sizeof(fakeStart)) != 0) return 0;
  return kSpoofStart;
}

uint32_t ApplyPost(void* mappedBase) {
  uint32_t mask = 0;
  mask |= EraseHeaders(mappedBase);
  mask |= UnlinkLdr(mappedBase);
  // NOTE: Hide/Spoof apply to payload-owned threads (Phase 05). Never touch the
  // hijacked game thread or the transient CRT thread here.
  return mask;
}

uint32_t HideCurrentThreadPub() { return HideCurrentThread(); }

} // namespace vacsafe::stealth
