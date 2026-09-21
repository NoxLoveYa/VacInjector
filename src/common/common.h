#pragma once
#include <cstdint>
#include <string>
#include <windows.h>

namespace vacsafe {

using BuildId = char[32];

enum class Arch { X86, X64, Unknown };

struct InjectorConfig {
  DWORD pid = 0;
  Arch arch = Arch::Unknown;
  enum class Method { Auto, ManualMapHijack, ManualMapRemoteThread, ManualMapApc, KernelMap } method = Method::Auto;
  std::wstring payloadPath;
  bool eraseHeaders = true;
  bool unlinkLdr = true;
  bool spoofStartAddr = true;
  bool preferStomp = false;
  DWORD timeoutMs = 5000;
};

struct InjectResult {
  LONG ntstatus = 0;
  void* injectedBase = nullptr;
  bool entryCalled = false;
  uint32_t stealthMask = 0;
  std::string error;
  bool ok() const { return ntstatus == 0 && injectedBase && entryCalled; }
};

#define VACSAFE_E_OPEN 0x100
#define VACSAFE_E_ALLOC 0x101
#define VACSAFE_E_RELOC 0x102
#define VACSAFE_E_IMPORT 0x103
#define VACSAFE_E_EXEC_TIMEOUT 0x104
#define VACSAFE_E_ARCH_MISMATCH 0x105
#define VACSAFE_E_UNKNOWN_GAME 0x106

} // namespace vacsafe
