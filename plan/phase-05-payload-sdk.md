# Phase 05 — Universal Payload SDK

**Goal:** One payload DLL that adapts to any VAC game via engine adapters.

## 5.1 SDK Core (`sdk/`)
- [ ] `IGameAdapter` + `GameContext` (pid, engine version, clientBase, engineBase, viewMatrix addr, entityList addr)
- [ ] `Memory` wrapper: `Read<T>(addr)`, `Write<T>`, `PatternScan(module, sig, mask)` with cached module bases, no `ReadProcessMemory` (internal RPM via direct deref + SEH guard)
- [ ] `Netvar/Schema` manager:
  - Source1: `client.dll!GetAllClasses` RecvTable walk
  - Source2/CS2: `schemasystem.dll!CSchemaSystem` — `FindTypeScopeForModule`, `FindDeclaredClass`, `GetFieldOffset`
- [ ] `Interface` capturer: `CreateInterface` factory brute-force (`VClient018` → `VClient019`, `VEngineClient014`, etc.) with fallback scan
- [ ] `Renderer` abstraction: `PresentHook` (DX9 `EndScene`, DX11 `Present`, Vulkan `vkQueuePresentKHR`) + `WorldToScreen(viewMatrix)` + `DrawList` (lines/boxes/text, no ImGui external window in Trusted)
- [ ] `Entity` model: unified `Player { pos, health, team, dormant, spotted, name }` normalized from `C_BaseEntity` / `C_CSPlayerPawn` / `C_TFPlayer`

## 5.2 Adapters (`payload/adapters/`)
- [ ] `cs2_adapter.cpp`: Source2, x64, `client.dll + engine2.dll`, Schema dump, `CGameEntitySystem`, `dwLocalPlayerPawn`, `dwEntityList`, `dwViewMatrix`
- [ ] `source1_adapter.cpp`: TF2/CSS/L4D2 shared base, `client.dll + engine.dll`, RecvProps, `GetClientEntity(i)`, `EngineTrace` ray
- [ ] `goldsrc_adapter.cpp` (stretch): HL1DM/CS1.6 if needed — `hw.dll` entities
- [ ] `adapter_factory.cpp`: detect via `GetModuleFileName(gameExe)` + PEB module presence → instantiate correct adapter, fail with `E_UNKNOWN_GAME` otherwise

## 5.3 Payload Entry (`payload/`)
- [ ] `dllmain.cpp`: `DisableThreadLibraryCalls`, `Stealth::ApplyPost()`, spawn init thread (hidden), `Sdk::Init(adapter)`, hot-unload on `VK_END` or IPC `unload` cmd
- [ ] Feature stubs v1 (prove SDK works, no ban-bait): `ESP box` (internal Present hook), `Bunnyhop` (`+jump` force), `NoFlash` (read-only demo) — all toggleable via `config.json`, default OFF
- [ ] IPC listener: named pipe client, commands `ping/unload/set_config/dump_offsets`, heartbeat every 5s to loader
- [ ] Crash guard: `__try/__except` around entity loop, `IsBadReadPtr`-free validation via `NtQueryVirtualMemory` check before deref, auto-detach on map unload (`level_shutdown` event)

## 5.4 Offset Management
- [ ] `payload/offsets/*.json` per game + version: `{ "buildDate": "...", "dwLocalPlayer": "0x...", ... }`
- [ ] `tools/dump_schema_cs2.py` + `pattern_resolver`: auto-update offsets via sigs on game update, loader warns if exe hash unknown
- [ ] Never hardcode absolute addresses in code — always `base + offset` resolved at init, logged for triage

## Exit Criteria
- [x] SDK core CRT-free (`peb.h` mirrors, `nt_api` GetModuleBase/GetProcByHash/ByName, pattern scan, RIP resolve, W2S math deferred): builds clean, busyloop regression green (factory null -> smoke only, no crash).
- [x] CS2 adapter v1: exe detect, module fill, 3-globals pattern scan (guarded), live Schema walk (indices 13/2, guarded), entity-count walk (no schema needed), local HP/team/pos when schema resolves, `VacSafe-cs2.txt` proof. Source1/GoldSrc = clean stubs (05b).
- [ ] Same `payload.dll` (x64) loads in CS2 + TF2-x64 `-insecure` and prints `Adapter: CS2/Source1 OK`, entity count >0 on local bot server — PENDING USER CS2 RUN (see Handoff below).
- [ ] `WorldToScreen` projects bot positions correctly, ESP boxes track through map change — renderer iteration (05b).
- [ ] Unload via IPC leaves game running, VAD clean, re-inject works without restart — IPC iteration (05b).

## Handoff: CS2 -insecure validation (operator runs)
1. Steam -> CS2 Properties -> Launch Options: `-insecure -novid`, launch, `map de_dust2` + `bot_add_ct` x3 (any map).
2. `VacSafe.exe --game cs2 --payload <path>\payload-test.enc --method auto` (double-click works too).
3. Expect `[ok]`, loader-side beep, `%TEMP%\VacSafe-cs2.txt` with `client=0x...`, 3 globals nonzero, `entities=N` (N>0 with bots), `schema=1` + `p0hp` if schema resolved.
4. Failure guide: `sig stale: dwX` -> CS2 updated past our sigs (paste new sig/RVA or fill `offsets/cs2.json`); `schema ... missing` -> vtable/layout drift (entity count still valid); `Source1 adapter...` on TF2 -> expected (05b).
5. Stay `-insecure` for all Phase 05 validation. No secure/MM until Phase 07 protocol on throwaways.

## Build Notes (2026-09-21 lab, Binja-verified on schemasystem.dll)
- CSchemaSystem vtable (len-40 table): [11]=GlobalTypeScope (returns `&g_GlobalScope`, no args), [12]=FindOrCreate (allocs 0x3640 scope on miss), [13]=FindTypeScopeForModule.
- TRUE signatures differ from public headers: System[13](this, name, outOrNull)->scope (2-arg call writes through garbage r8); Scope[2](this, out**, name)->void (2-arg call misreads rax). Code passes 3 args both. 2-arg failures were silent before (guarded) — never crashes, but schema could never succeed.
- `VACSAFE_NOCALL`/`VACSAFE_CRTNOCALL` diag gates remain for mechanics probes.
