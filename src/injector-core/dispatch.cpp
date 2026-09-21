#include "injector_core.h"
// TODO Phase 03: dispatch Auto -> Hijack -> APC, minimal-rights open, RAII cleanup, arch check.
namespace vacsafe {
HANDLE OpenGameMinimal(DWORD, std::string& err) { err = "not implemented (Phase 03)"; return nullptr; }
InjectResult Inject(const InjectorConfig&) {
  InjectResult r; r.ntstatus = (LONG)0xC0000001; r.error = "not implemented (Phase 03)";
  return r;
}
}
