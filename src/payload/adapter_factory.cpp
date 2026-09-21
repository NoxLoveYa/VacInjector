#include "game_adapter.h"
// TODO Phase 05: exe-name detect -> CS2 vs Source1 vs GoldSrc adapter.
namespace vacsafe::sdk {
IGameAdapter* CreateAdapterFromExe(const std::string&) { return nullptr; }
}
