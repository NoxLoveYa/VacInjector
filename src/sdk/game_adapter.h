#pragma once
#include <cstdint>
#include <string>
#include <vector>
// Universal game-agnostic SDK. Phase 05 implements per-engine adapters.
namespace vacsafe::sdk {
struct Vec3 { float x, y, z; };
struct Player { Vec3 pos{}; int health = 0; int team = 0; bool dormant = true; std::string name; };
struct GameContext {
  uint32_t appId = 0;
  std::string exeName;
  uintptr_t clientBase = 0;
  uintptr_t engineBase = 0;
};
class IGameAdapter {
public:
  virtual ~IGameAdapter() = default;
  virtual const char* Name() const = 0;
  virtual bool Init(const GameContext& ctx, std::string& err) = 0;
  virtual std::vector<Player> GetPlayers() = 0;
  virtual bool WorldToScreen(const Vec3& w, Vec3& s) = 0;
};
IGameAdapter* CreateAdapter(const std::string& exeName); // factory, Phase 05
template <typename T> T Read(uintptr_t addr) { __try { return *(volatile T*)addr; } __except (EXCEPTION_EXECUTE_HANDLER) { return T{}; } }
uintptr_t PatternScan(uintptr_t base, size_t size, const char* sig, const char* mask); // Phase 05
} // namespace vacsafe::sdk
