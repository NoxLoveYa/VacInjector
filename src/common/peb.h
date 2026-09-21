#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstddef>
#include <cstdint>
// Shared PEB/LDR mirrors (Phase 05). SDK winternl.h redacts these (only
// InMemoryOrderModuleList is public), so we mirror the stable ABI layout.
// InMemoryOrder offset 0x20 verified against the public SDK header.
// CRT-free: usable on the payload raw-DllMain path.
namespace vacsafe::peb {

struct LdrData {
  uint8_t pad0[16];
  LIST_ENTRY InLoadOrderModuleList;   // +0x10
  LIST_ENTRY InMemoryOrderModuleList; // +0x20
  LIST_ENTRY InInitOrderModuleList;   // +0x30
};

struct LdrEntry {
  LIST_ENTRY InLoadOrderLinks;   // +0x00
  LIST_ENTRY InMemoryOrderLinks; // +0x10
  LIST_ENTRY InInitOrderLinks;   // +0x20
  void* DllBase;                 // +0x30
  void* EntryPoint;              // +0x38
  ULONG SizeOfImage;             // +0x40
  UNICODE_STRING FullDllName;    // +0x48
  UNICODE_STRING BaseDllName;    // +0x58
};

inline PEB* CurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }

} // namespace vacsafe::peb
