#pragma once
#include <cstdint>
// Stealth lib linked into loader (Pre) + payload (Post). Phase 04 implements.
namespace vacsafe::stealth {
constexpr uint32_t kEraseHeaders = 1 << 0;
constexpr uint32_t kUnlinkLdr    = 1 << 1;
constexpr uint32_t kSpoofStart   = 1 << 2;
constexpr uint32_t kHideThread   = 1 << 3;
uint32_t ApplyPre();
uint32_t ApplyPost(void* mappedBase);
void Wipe(void* ptr, size_t len);
} // namespace vacsafe::stealth
