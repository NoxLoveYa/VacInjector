# Target Matrix — VAC Games (Phase 02 Deliverable)

## Summary Table

| Tier | Game | AppID | Exe (default) | Arch | Engine | Renderer | VAC | Trusted |
|------|------|-------|---------------|------|--------|----------|-----|---------|
| 1 | Counter-Strike 2 | 730 | `cs2.exe` | x64 | Source 2 | DX11 / Vulkan | VAC + VAC Live (mid-match disrupt) | Yes — Trusted Mode, `-allow_third_party_software` disables |
| 2 | Team Fortress 2 | 440 | `tf_win64.exe` (default since Apr 18 2024 64-bit update), legacy `tf.exe` x86 retained for tools | x64 primary / x86 legacy | Source 1 (TF branch) | DX9 | VAC | No |
| 2 | Counter-Strike: Source | 240 | `hl2.exe` `-game cstrike` | x86 | Source 1 | DX9 | VAC | No |
| 2 | Left 4 Dead 2 | 550 | `left4dead2.exe` | x86 | Source 1 (L4D branch) | DX9 | VAC | No |
| 2 | Garry's Mod | 4000 | `gmod.exe` (renamed from `hl2.exe`, 2024+), beta `x86-64 - Chromium + 64-bit binaries` branch | x86 stable / x64 beta | Source 1 + LuaJIT | DX9 | VAC | No |
| 3 | DOD:S / HL2:DM / generic | 300 / 320 / etc | `hl2.exe` `-game dod/hl2mp` | x86 | Source 1 | DX9 | VAC | No |

## Per-Game Baselines

### CS2 (Tier 1)
- Launch: `cs2.exe`, Steam launch with Trusted by default. Flags: `-insecure` skips Trusted + VAC (lab only), `-allow_third_party_software` boots without Trusted (no official MM trust), `-trusted` forces full catalog verify.
- Modules: `client.dll`, `engine2.dll`, `schemasystem.dll` (`SchemaSystem_001`), `tier0.dll` (`Plat_RegisterModule`), `materialsystem2`, `rendersystemvulkan/dx11`, `gameoverlayrenderer64.dll`, `steam_api64.dll`.
- Schema: `CSchemaSystem` type scopes per module, `FindTypeScopeForModule` → `FindDeclaredClass` → field offsets. Offsets (`dwEntityList`, `dwLocalPlayerPawn`, `dwViewMatrix`) via `a2x/cs2-dumper` sigs, refreshed per update.
- Integrity: Protected Process Light? No — normal Medium IL, but Trusted Launch catalogs block unsigned opens. Handle: open with minimal rights, never `PROCESS_ALL_ACCESS`.
- Adapters: `cs2_adapter.cpp`, x64 only, WoW64 bridge not needed.

### TF2 (Tier 2 reference Source 1)
- Launch history: `hl2.exe -steam -game tf` → now `tf_win64.exe` default, `tf.exe` launches 32-bit insecure by default (needs `-steam` for VAC secure; Steam client launches x64 path automatically).
- Modules: `client.dll`, `engine.dll` (`bin/x64/engine.dll` + `bin/engine.dll` legacy), `server.dll`, `vstdlib.dll`, `tier0.dll`. RecvTables via `client.dll!GetAllClasses`.
- VAC module file historic: `resource\sourceinit.dat`, `vacmodulecache 202`. Signed files list includes `hl2.exe`, `client.dll`, `engine.dll`.
- Test flags: `-insecure` (no VAC, local server), `-steam -game tf` for secure path.
- Adapters: `source1_adapter.cpp` covers TF2/CSS/L4D2 via interface versions (`VClient018`→, `VEngineClient014`→).

### CSS / L4D2 / GMod notes
- CSS: `hl2.exe`, AppID 240, x86 only, same RecvTable path as TF2, `engine.dll` + `client.dll` in `cstrike/bin`.
- L4D2: `left4dead2.exe`, AppID 550, x86, L4D engine fork (different `C_TerrorPlayer` layout — adapter quirk, same interface capture).
- GMod: `gmod.exe`, AppID 4000, x86 stable default; x64 only on `x86-64` beta. LuaJIT x64 perf regressions + few third-party binary modules for x64 — injector must support both archs, APC fallback for Lua threads. `garrysmod/lua/bin` module path is extra scan surface.

## Steam + VAC File Layout
- `SteamService.exe` + `steamservice.dll`: VAC core loader. Historic: `steamservice.dll` in `SteamService.exe` when Steam non-admin, in `steam.exe` when admin. Current (2025-2026 reports): consistently in `SteamService.exe`.
- Streamed modules (legacy, now largely disabled per community 2025-2026): entry `_runfunc@20`, two loads — manual-map (memory-only) vs `LoadLibrary` via `%TEMP%/*.tmp` drop. Dumper technique: patch `ExecVacModule` JZ→JNZ (`F6 45 0C 02 74 ??`) to force disk path, ProcMon `%TEMP%` for `.TMP`. VLV signature at `DOS_HEADER+0x40`.
- Current CS2 split (per `cs2-vac-internals` + `cs2-anticheat`):
  - `cs2.exe` Trusted Launch pre-engine: 4 sig catalogs (`CryptCatAdminAcquireContext2`), 3 API hooks incl. `NtOpenFile` gate (`DesiredAccess & 0x21` → catalog check, unsigned → `0xC0000034`), VEH registered.
  - `client.dll` in-process: `CDllVerificationMonitor`, protobuf `CSVCMsg_UserMessage` slots 158/159/161/162/163/164/385 over `g_pNetworkChannel`.
  - `steam.exe` external: `NtReadVirtualMemory` + `NtQueryVirtualMemory` only, 4 handles cross-verify, pure usermode, no driver.
- Service helpers: `bin/steamservice.exe`, `bin/GameOverlayRenderer.dll`, `config/loginusers.vdf` (account correlation surface — use throwaways).

## Handle / IL / Launch Cheat-Sheet
- IL: all games Medium, none PPL. No admin needed for UM inject. Admin only needed for driver path or `ReadProcessMemory` on elevated Steam.
- Rights: `PROCESS_VM_OPERATION | VM_READ | VM_WRITE | QUERY_INFORMATION | CREATE_THREAD | SUSPEND_RESUME`. Never `0x1FFFFF`.
- Lab: `game.exe -insecure + map bot arena + sv_cheats 0` for logic; `game.exe` + local bot server VAC-enabled for scan validation; MM only on throwaway, one BUILD_ID per account.
