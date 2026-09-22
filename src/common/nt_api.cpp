#include "nt_api.h"
#include "peb.h"
#include <windows.h>
#include <winternl.h>
#include <cstddef>

// Hash-resolved imports: no IAT strings for sensitive APIs (Phase 04).
// CRT-free TU: safe on the payload raw-DllMain path (no printf/malloc/new).
namespace vacsafe::nt {

uint32_t HashName(const char* s) {
  uint32_t h = 5381;
  while (*s) h = ((h << 5) + h) + (uint8_t)*s++;
  return h;
}

static bool NameEqI(const wchar_t* a, const wchar_t* mod) {
  if (!a || !mod) return false;
  for (int i = 0; i < 72; ++i) {
    wchar_t ca = a[i], cb = mod[i];
    if (ca >= L'A' && ca <= L'Z') ca += 32;
    if (cb >= L'A' && cb <= L'Z') cb += 32;
    if (!cb && !ca) return true;
    if (!cb || !ca || ca != cb) return false;
  }
  return false;
}

static int StrEq(const char* a, const char* b) {
  while (*a && *a == *b) { ++a; ++b; }
  return *a == *b;
}

void* GetModuleBase(const wchar_t* module) {
  __try {
    PEB* peb = peb::CurrentPeb();
    if (!peb || !peb->Ldr || !module) return nullptr;
    auto* ldr = (peb::LdrData*)peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
      auto* e = (peb::LdrEntry*)((uint8_t*)cur - offsetof(peb::LdrEntry, InMemoryOrderLinks));
      if (NameEqI(e->BaseDllName.Buffer, module)) return e->DllBase;
    }
    return nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static void* ExportLookupRec(void* modBase, uint32_t hash, const char* name, int depth) {
  auto* dos = (IMAGE_DOS_HEADER*)modBase;
  if (!modBase || depth > 3 || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
  auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)modBase + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
  if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return nullptr;
  auto& exp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!exp.VirtualAddress) return nullptr;
  auto* dir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)modBase + exp.VirtualAddress);
  auto* names = (DWORD*)((uint8_t*)modBase + dir->AddressOfNames);
  auto* ords = (WORD*)((uint8_t*)modBase + dir->AddressOfNameOrdinals);
  auto* funcs = (DWORD*)((uint8_t*)modBase + dir->AddressOfFunctions);
  for (DWORD i = 0; i < dir->NumberOfNames; ++i) {
    const char* nm = (const char*)((uint8_t*)modBase + names[i]);
    bool hit = name ? StrEq(nm, name) : (HashName(nm) == hash);
    if (!hit) continue;
    WORD ord = ords[i];
    if ((DWORD)ord >= dir->NumberOfFunctions) return nullptr;
    DWORD rva = funcs[ord];
    if (rva >= exp.VirtualAddress && rva < exp.VirtualAddress + exp.Size) {
      // Forwarded export ("GDI32.Rectangle"): follow into the target module.
      const char* fwd = (const char*)((uint8_t*)modBase + rva);
      const char* dot = nullptr;
      for (const char* p = fwd; *p && (size_t)(p - fwd) < 64; ++p) {
        if (*p == '.') { dot = p; break; }
      }
      if (!dot || dot == fwd) return nullptr;
      // module part -> wide name + ".dll" (caller stack, no CRT)
      wchar_t wmod[32]{};
      size_t k = 0;
      for (const char* p = fwd; p < dot && k + 5 < 32; ++p, ++k) {
        char c = *p;
        if (c >= 'a' && c <= 'z') c -= 32; // compare is case-insensitive anyway
        wmod[k] = (wchar_t)c;
      }
      wmod[k++] = L'.';
      wmod[k++] = L'd'; wmod[k++] = L'l'; wmod[k++] = L'l';
      wmod[k] = 0;
      void* tgt = GetModuleBase(wmod);
      if (!tgt) return nullptr;
      if (dot[1] == '#') return nullptr; // ordinal forward: unsupported, fail closed
      return ExportLookupRec(tgt, 0, dot + 1, depth + 1);
    }
    return (uint8_t*)modBase + rva;
  }
  return nullptr;
}

static void* ExportLookup(void* modBase, uint32_t hash, const char* name) {
  return ExportLookupRec(modBase, hash, name, 0);
}

void* GetProcByHash(const wchar_t* module, uint32_t hash) {
  __try {
    return ExportLookup(GetModuleBase(module), hash, nullptr);
  } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

void* GetProcByName(void* modBase, const char* name) {
  __try {
    if (!modBase || !name) return nullptr;
    return ExportLookup(modBase, 0, name);
  } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static size_t ModSize(void* base) {
  auto* dos = (IMAGE_DOS_HEADER*)base;
  if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
  auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
  DWORD sz = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
      ? ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SizeOfImage
      : ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SizeOfImage;
  return (sz && sz < 0x40000000) ? sz : 0;
}

bool AddressInModules(uintptr_t addr) {
  __try {
    if (!addr) return false;
    PEB* peb = peb::CurrentPeb();
    if (!peb || !peb->Ldr) return false;
    auto* ldr = (peb::LdrData*)peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
      auto* e = (peb::LdrEntry*)((uint8_t*)cur - offsetof(peb::LdrEntry, InMemoryOrderLinks));
      uintptr_t b = (uintptr_t)e->DllBase;
      size_t s = ModSize(e->DllBase);
      if (b && s && addr >= b && addr < b + s) return true;
    }
    return false;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

} // namespace vacsafe::nt
