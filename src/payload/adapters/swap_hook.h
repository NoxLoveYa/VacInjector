#pragma once
#include <windows.h>
#include <cstdint>
// Swapchain acquisition + Present hook surface (Phase 05b-iii).
// Strategy: hidden 1x1 window -> own D3D11 device+swapchain -> vtable address ->
// RefSearch target memory for the GAME's swapchain instance -> shadow-VMT hook.
// CRT-free: hashed APIs only, no heap-new, SEH/VQ-guarded reads.
namespace vacsafe {

struct SwapHit {
  void* swapchain = nullptr; // game instance (not ours)
  void* vtable = nullptr;    // shared IDXGISwapChain vtable
  void* present = nullptr;   // vtable[8]
  int scannedMB = 0;
  int hits = 0;
};

// Find the game's IDXGISwapChain. Returns true with hit filled. Fail-closed.
bool AcquireSwapchain(SwapHit* out);

} // namespace vacsafe
