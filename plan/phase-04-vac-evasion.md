# Phase 04 — VAC Evasion & Stealth

**Goal:** Survive every scan category from Phase 01. Stealth is a library, not an afterthought.

## 4.1 Pre-Inject (loader-side)
- [ ] Randomize all names per boot: pipe name, event name, mutex, temp file (if any) with `BCryptGenRandom`
- [ ] Strip loader artifacts: no window title `VacSafe`, no `VERSIONINFO` cheat strings, icon + metadata mimic `svchost`
- [ ] ETW + AMSI hygiene in loader only: `EtwEventWrite` patch in own process (not game), to hide packer behavior from local EDR; never patch game ETW (detectable)
- [ ] Delay + jitter: random 500-2500ms between open → alloc → write → exec to break timing sigs
- [ ] No RWX in loader for unpacked payload longer than needed; `VirtualProtect(RW->RX)` then wipe after copy

## 4.2 Post-Inject (payload-side, `Stealth::ApplyPost`)
- [ ] `EraseHeaders`: zero `DOS_HEADER`, `NT_HEADERS`, section headers in mapped image
- [ ] `UnlinkLdr`: remove from `PEB_LDR_DATA` (`InLoadOrder/InMemoryOrder/InInitOrder`) via `LdrLockLoaderLock`, keep `LdrpHashTable` consistent
- [ ] `SpoofStartAddr`: `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` → set to `kernel32!BaseThreadInitThunk` via `NtSetInformationThread`
- [ ] `VAD Spoof`: set allocation to `MEM_IMAGE` lookalike where possible; split `.text` RX private → avoid single large RX private blob; use `PAGE_EXECUTE_READ` not `RWX`
- [ ] `HideThread`: `NtSetInformationThread(ThreadHideFromDebugger)` on payload threads
- [ ] `Module Stomp option`: overwrite dead game module slack (e.g., `crashhandler.dll` `.text` padding) instead of fresh alloc — config flag `preferStomp=true` for high-risk games
- [ ] No hooks on `ntdll.dll` exports VAC checks; if hooking Present/VMT for ESP, use shadow VMT copy + pointer swap, restore on unload, never inline `0xE9 JMP` on engine `.text`

## 4.3 Runtime Hygiene (always-on)
- [ ] String encryption: all scan-sensitive strings (`client.dll`, `vac`, `cheat`, feature names) as `XOR-encrypted` at compile, decrypted stack-only
- [ ] Import hashing: no IAT entries for `ReadProcessMemory`, `CreateFileW`, `DeviceIoControl`, `Nt*` — resolve via `PEB walk + hash`
- [ ] No overlay window: render via hooked game Present (internal) not external `Topmost+Transparent+LWA` window; external overlay = instant VAC Live flag in CS2
- [ ] Config + log on disk encrypted; log path outside game dir, never `C:\VacSafe\`
- [ ] Heartbeat killer: block payload from opening sockets; loader does version check over HTTPS with generic UA, payload stays offline

## 4.4 Polymorphism (per-build uniqueness)
- [ ] `tools/pack_payload.py`: ChaCha20 encrypt + per-build junk sections + section name randomize + timestamp randomize + GUID rebuild
- [ ] `gen_build_id.py`: embeds `BUILD_ID` + asserts loader/payload match, prevents mixing sigs across bans
- [ ] Ban = burn build: never reuse payload bytes after any ban in test lab

## Exit Criteria
- [ ] `stealth/` passes `VAC checklist`: ProcessHacker shows no private RX > 200KB with no file backing, no `MZ`, `gh_flag` scanner (community VAD scanner) reports clean
- [ ] String scan (`strings.exe` on dump of game memory) finds zero hits for `VacSafe`, `payload.dll`, feature keywords
- [ ] 24h idle in `-insecure` + local bot match with payload loaded, no crash, no integrity error in console
