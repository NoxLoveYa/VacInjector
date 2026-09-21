#pragma once
#include <windows.h>
#include "nt_api.h"
// Shared hashed kernel32 API table for payload-owned code (Phase 04/05).
// Zero plaintext imports: hashes are djb2 of export names (computed offline).
// CRT-free: safe on the raw-DllMain path.
namespace vacsafe {

using BeepFn = BOOL (WINAPI*)(DWORD, DWORD);
using GetTempPathAFn = DWORD (WINAPI*)(DWORD, LPSTR);
using CreateFileAFn = HANDLE (WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using WriteFileFn = BOOL (WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using CloseHandleFn = BOOL (WINAPI*)(HANDLE);
using DisableTlFn = BOOL (WINAPI*)(HMODULE);
using OdsFn = void (WINAPI*)(LPCSTR);
using CreateThreadFn = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using GetModuleFileNameAFn = DWORD (WINAPI*)(HMODULE, LPSTR, DWORD);

struct Api {
  BeepFn beep = nullptr;
  GetTempPathAFn getTempPath = nullptr;
  CreateFileAFn createFile = nullptr;
  WriteFileFn writeFile = nullptr;
  CloseHandleFn close = nullptr;
  DisableTlFn disableTl = nullptr;
  OdsFn ods = nullptr;
  CreateThreadFn createThread = nullptr;
  GetModuleFileNameAFn getModuleFileName = nullptr;
  // djb2: Beep=0x7C82FBA1 GetTempPathA=0x9EF979E9 CreateFileA=0xEB96C5FA
  // WriteFile=0x663CECB0 CloseHandle=0x3870CA07 DisableThreadLibraryCalls=0x530574F5
  // OutputDebugStringA=0x79729F95 CreateThread=0x7F08F451 GetModuleFileNameA=0x13B8A14D
  bool Resolve() {
    beep = (BeepFn)nt::GetProcByHash(L"kernel32.dll", 0x7C82FBA1);
    getTempPath = (GetTempPathAFn)nt::GetProcByHash(L"kernel32.dll", 0x9EF979E9);
    createFile = (CreateFileAFn)nt::GetProcByHash(L"kernel32.dll", 0xEB96C5FA);
    writeFile = (WriteFileFn)nt::GetProcByHash(L"kernel32.dll", 0x663CECB0);
    close = (CloseHandleFn)nt::GetProcByHash(L"kernel32.dll", 0x3870CA07);
    disableTl = (DisableTlFn)nt::GetProcByHash(L"kernel32.dll", 0x530574F5);
    ods = (OdsFn)nt::GetProcByHash(L"kernel32.dll", 0x79729F95);
    createThread = (CreateThreadFn)nt::GetProcByHash(L"kernel32.dll", 0x7F08F451);
    getModuleFileName = (GetModuleFileNameAFn)nt::GetProcByHash(L"kernel32.dll", 0x13B8A14D);
    return beep && getTempPath && createFile && writeFile && close && disableTl && ods && createThread && getModuleFileName;
  }
  // Basename of current process image into out (no CRT). "C:\...\cs2.exe" -> "cs2.exe".
  void ExeName(char* out, size_t cap) const {
    if (!out || !cap) return;
    out[0] = 0;
    char full[MAX_PATH];
    DWORD n = getModuleFileName(nullptr, full, (DWORD)sizeof(full));
    if (!n || n >= sizeof(full)) return;
    size_t start = 0;
    for (size_t i = 0; i < n; ++i)
      if (full[i] == '\\' || full[i] == '/') start = i + 1;
    size_t o = 0;
    for (size_t i = start; i < n && o + 1 < cap; ++i) out[o++] = full[i];
    out[o] = 0;
  }
};

} // namespace vacsafe
