#include "stealth.h"
#include <windows.h>
namespace vacsafe::stealth {
uint32_t ApplyPre() { return 0; } // TODO Phase 04: randomize names, ETW hygiene self-only, jitter
uint32_t ApplyPost(void*) { return 0; } // TODO Phase 04: erase headers, unlink LDR, spoof start, hide thread
void Wipe(void* p, size_t n) { SecureZeroMemory(p, n); }
}
