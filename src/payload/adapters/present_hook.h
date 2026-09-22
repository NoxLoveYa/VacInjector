#pragma once
#include <windows.h>
#include "game_adapter.h"
// DXGI Present hook (Phase 05b-iii): shadow-VMT hook on the game's swapchain,
// D3D11 line rendering with embedded shaders. CRT-free, hashed APIs, guarded.
namespace vacsafe {

// Installs hkPresent on the acquired swapchain. needs: adapter+ctx for boxes,
// api for VirtualAlloc. Returns false to fall back to GDI.
struct Api;
bool InstallPresentHook(void* swapchain, void* vtable, void* origPresent,
                        const sdk::IGameAdapter* ad, sdk::GameContext* ctx,
                        const Api* api);

} // namespace vacsafe
