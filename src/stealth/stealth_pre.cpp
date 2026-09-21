#include "stealth.h"
#include <windows.h>

// Loader-side only TU. Full CRT is available here (normal console entry).
// Kept separate from stealth.cpp so the payload never links these imports.
namespace vacsafe::stealth {

uint32_t ApplyPre() {
  // Timing jitter to break inject-timing sigs (100-400ms).
  ULONGLONG t = GetTickCount64();
  DWORD jitter = 100 + (DWORD)((t ^ (t >> 11)) % 300);
  Sleep(jitter);
  return 0;
}

} // namespace vacsafe::stealth
