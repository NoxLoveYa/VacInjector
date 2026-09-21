#pragma once
#include "common.h"
namespace vacsafe {
// Phase 03: pure injection API. No game logic here.
InjectResult Inject(const InjectorConfig& cfg);
void* ManualMap(HANDLE hProc, const uint8_t* image, size_t size, std::string& err);
bool ExecViaHijack(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err);
bool ExecViaApc(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err);
HANDLE OpenGameMinimal(DWORD pid, std::string& err);
} // namespace vacsafe
