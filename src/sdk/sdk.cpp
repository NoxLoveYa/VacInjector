#include "game_adapter.h"
namespace vacsafe::sdk {
IGameAdapter* CreateAdapter(const std::string&) { return nullptr; } // TODO Phase 05
uintptr_t PatternScan(uintptr_t, size_t, const char*, const char*) { return 0; } // TODO Phase 05
}
