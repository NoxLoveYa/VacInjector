#pragma once
#include "common.h"
namespace vacsafe {
// Phase 03: pure injection API. No game logic here.
// NOTE: CreateRemoteThread is used ONLY with our ManualMap stub (never LoadLibrary):
// image stays unlinked/header-erased; thread exits via RtlExitUserThread in ms and the
// stub is freed immediately. Hijack stays default (no new thread); CRT is fallback when
// every candidate thread is parked in a kernel wait (RIP redirect would wait forever).
InjectResult Inject(const InjectorConfig& cfg);
void* ManualMap(HANDLE hProc, const uint8_t* image, size_t size, std::string& err);
bool ExecViaHijack(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err);
bool ExecViaRemoteThread(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err);
bool ExecViaApc(HANDLE hProc, void* entry, void* arg, DWORD timeoutMs, std::string& err);
HANDLE OpenGameMinimal(DWORD pid, std::string& err);
} // namespace vacsafe
