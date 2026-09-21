#include "game_adapter.h"

// Adapter factory: exe basename -> const adapter table (Phase 05 v1).
// Tables are constant-initialized (no dynamic init -> raw-DllMain safe).
// Source1/GoldSrc land in Phase 05b; unknown exes fail closed with E_UNKNOWN_GAME.
namespace vacsafe {

extern const sdk::IGameAdapter kCs2Adapter;

namespace {
const char* S1Name() { return "source1/stub"; }
bool S1Init(sdk::GameContext* ctx) {
  sdk::SetErr(ctx, "Source1 adapter lands in Phase 05b (CS2 only for v1)");
  return false;
}
int S1Players(sdk::GameContext*, sdk::Player*, int) { return 0; }
bool S1W2S(sdk::GameContext*, const sdk::Vec3&, sdk::Vec3&) { return false; }
const sdk::IGameAdapter kSource1Stub = { S1Name, S1Init, S1Players, S1W2S };

bool ExeIs(const char* exe, const char* want) {
  if (!exe || !want) return false;
  size_t i = 0;
  for (;; ++i) {
    char a = exe[i], b = want[i];
    if (a >= 'A' && a <= 'Z') a += 32;
    if (b >= 'A' && b <= 'Z') b += 32;
    if (!a && !b) return true;
    if (!a || !b || a != b) return false;
    if (i > 40) return false;
  }
}
} // namespace

const sdk::IGameAdapter* CreateAdapterForExe(const char* exeName) {
  if (!exeName || !exeName[0]) return nullptr;
  if (ExeIs(exeName, "cs2.exe")) return &kCs2Adapter;
  if (ExeIs(exeName, "tf_win64.exe") || ExeIs(exeName, "tf.exe") ||
      ExeIs(exeName, "hl2.exe") || ExeIs(exeName, "left4dead2.exe") ||
      ExeIs(exeName, "gmod.exe"))
    return &kSource1Stub;
  return nullptr;
}

} // namespace vacsafe
