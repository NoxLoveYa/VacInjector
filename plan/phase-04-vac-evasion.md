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
- [x] `stealth/` core lands: `ApplyPost` erases headers (remote-verified zeros via RPM), `UnlinkLdr` verify+detach, `HideThread`/`SpoofStart` hash-resolved helpers ready for Phase 05 threads. Private RX mapping is small (payload ~16KB, stubs <8KB, freed post-entry); `MZ` absent post-attach. ProcessHacker + `gh_flag` manual pass pending on game target.
- [x] String scan: `payload.dll` binary has zero hits for `VacSafe`/`smoke`/`Beep`/`CreateFileA`/`OutputDebugStringA` (obfuscation + hashed imports); `.enc` at rest has no `MZ`/strings. Memory-dump scan pending on game target.
- [ ] 24h idle in `-insecure` + local bot match with payload loaded, no crash, no integrity error in console

## Build Notes (2026-09-21 lab)
- `obf.h`: compile-time XOR, stack-only plaintext, literal-only + no-store rules. Applied to all payload literals.
- `nt_api.cpp`: PEB-walk + djb2 resolver, CRT-free. Payload owns hashed `Api` struct (7 kernel32 APIs); IAT holds EH-machinery only.
- At-rest: `pack_payload.py` XOR/BUILD_ID + sidecar `.map`; dispatch decrypts `.enc`, resolves raw `DllMain` from sidecar. CRT-entry fallback kept for foreign DLLs (fragile with our payload, fine for normal-IAT DLLs).
- Deferred: module-stomp, ETW self-hygiene, ChaCha20 upgrade, config/log encryption (no config exists yet), socket block (payload opens none).
