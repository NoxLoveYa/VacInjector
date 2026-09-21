#include "injector_core.h"
// TODO Phase 03: QueueUserAPC fallback for alertable threads (GMod etc).
namespace vacsafe {
bool ExecViaApc(HANDLE, void*, void*, DWORD, std::string& err) { err = "not implemented (Phase 03)"; return false; }
}
