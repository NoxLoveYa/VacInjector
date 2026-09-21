#include "injector_core.h"
// TODO Phase 03: PE parse, reloc, import-by-hash, section protect, header erase staging.
namespace vacsafe {
void* ManualMap(HANDLE, const uint8_t*, size_t, std::string& err) { err = "not implemented (Phase 03)"; return nullptr; }
}
