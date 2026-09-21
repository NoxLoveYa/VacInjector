#include "injector_core.h"
// TODO Phase 03: suspend worker thread, SetThreadContext RIP -> x64_stub, resume, wait event, restore.
namespace vacsafe {
bool ExecViaHijack(HANDLE, void*, void*, DWORD, std::string& err) { err = "not implemented (Phase 03)"; return false; }
}
