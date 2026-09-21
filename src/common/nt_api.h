#pragma once
#include "common.h"
// NT API + module helpers, hash-resolved at runtime (no IAT strings for sensitive APIs).
// CRT-free: safe on the payload raw-DllMain path.
namespace vacsafe::nt {
void* GetProcByHash(const wchar_t* module, uint32_t hash);
uint32_t HashName(const char* s);
// Base address of a loaded module (case-insensitive), or nullptr.
void* GetModuleBase(const wchar_t* module);
// Export lookup by (obfuscated) name. Use with VACSAFE_OBF at the call site.
void* GetProcByName(void* modBase, const char* name);
// True when addr falls inside any loaded module image. Pre-call gate for vtable
// targets: refuses wild jumps from stale indices (fail closed, no crash).
bool AddressInModules(uintptr_t addr);
} // namespace vacsafe::nt
