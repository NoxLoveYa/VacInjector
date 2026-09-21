#include "nt_api.h"
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

struct LdrEntry {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitOrderLinks;
  void* DllBase;
  void* EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
};

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

void* GetProcByHash(const wchar_t* module, uint32_t hash) {
  __try {
    PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb || !peb->Ldr || !module) return nullptr;
    HMODULE base = nullptr;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
      auto* e = (LdrEntry*)((uint8_t*)cur - offsetof(LdrEntry, InMemoryOrderLinks));
      if (NameEqI(e->BaseDllName.Buffer, module)) { base = (HMODULE)e->DllBase; break; }
    }
    if (!base) return nullptr;
    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return nullptr;
    auto& exp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp.VirtualAddress) return nullptr;
    auto* dir = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)base + exp.VirtualAddress);
    auto* names = (DWORD*)((uint8_t*)base + dir->AddressOfNames);
    auto* ords = (WORD*)((uint8_t*)base + dir->AddressOfNameOrdinals);
    auto* funcs = (DWORD*)((uint8_t*)base + dir->AddressOfFunctions);
    for (DWORD i = 0; i < dir->NumberOfNames; ++i) {
      const char* nm = (const char*)((uint8_t*)base + names[i]);
      if (HashName(nm) != hash) continue;
      WORD ord = ords[i];
      if ((DWORD)ord >= dir->NumberOfFunctions) return nullptr;
      DWORD rva = funcs[ord];
      if (rva >= exp.VirtualAddress && rva < exp.VirtualAddress + exp.Size) return nullptr; // forwarded
      return (uint8_t*)base + rva;
    }
    return nullptr;
  } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

} // namespace vacsafe::nt
