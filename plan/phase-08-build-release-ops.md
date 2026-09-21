# Phase 08 — Build Pipeline, Release, Ops & Updates

**Goal:** Every release is fresh, reproducible, and burnable. Game update ≠ panic.

## 8.1 Build System (`build/`)
- [ ] `CMakePresets.json`: `x64-release`, `x86-release`, `tests`, `driver-test-sign`
- [ ] `build.bat`: clean `build/x64` + `build/x86`, `gen_build_id.py` → `BUILD_ID` header, `pack_payload.py` encrypts `payload.dll` → `payload-<BUILD_ID>.enc`, hashes to `release-notes.md`
- [ ] Compiler flags: `/O2 /GL /guard:cf-` (CF off for shellcode compat — document why), `/DYNAMICBASE`, no PDB in release, `.reloc` kept for ManualMap
- [ ] Reproducible-ish: same source + same seed = same bytes for triage; release uses random seed for polymorphism
- [ ] Pre-commit: `hash_imports.py` fails if new plaintext banned import added (`LoadLibraryA`, `CreateRemoteThread`, `SetWindowsHookEx`)

## 8.2 Polymorphism & Release Hygiene
- Per release: fresh junk code (`__nop` sleds with random registers), section rename (` .rdata` → `.pdata`-like mimic), timestamp jitter, version-info clone from legit DLL
- Never publish payload hash, never upload `.enc` to VirusTotal (burns sig), local `Defender` exclusion only in lab VM
- Release bundle: `VacSafe-<BUILD_ID>.zip` = `VacSafe.exe (x64+x86 helper) + payload-<BUILD_ID>.enc + config.json.enc + README`
- `release-notes.md` per BUILD_ID: game hashes tested, method used, known issues, `BURNED` flag if banned

## 8.3 Game Update Response (Steam breaks offsets weekly)
- [ ] Watcher: `tools/check_update.py` polls exe hash + `offsets/*.json` validity; loader warns `Unknown game build — update offsets?` and refuses inject rather than crashing
- [ ] Offset refresh flow: dump new Schema via `dump_schema_cs2.py` → update sigs → `test_offsets` → new BUILD_ID → lab smoke test → release
- [ ] VAC module change: re-dump streamed modules monthly, update `vac-threat-model.md`, adjust stealth if new `NtAPI` appears in imports

## 8.4 Ops Rules
- One build per account set, throwaway accounts only, no sharing builds across users in v1 (correlation = mass ban)
- No remote kill-switch, no loader auto-download of payload bytes over HTTP (MITM + sig risk) — manual zip drop
- Log retention: local 7 days, encrypted; `wipe` command does `cipher /w` on log dir + `SecureZeroMemory` on RAM keys
- Roadmap after v1: `Vulkan Present hook polish`, `GMod Lua bypass adapter`, `KM hide assist` if UM proves insufficient for CS2 Trusted

## Exit Criteria (v1 Ship)
- [ ] `build.bat` green x86+x64, tests green, `gh_flag` clean, manual checklist signed for 2 games
- [ ] Release zip + release-notes for BUILD_ID, ban-log ready, update watcher running
- [ ] Next phase kicked: pick first live-fire game (TF2 casual throwaway) with one-variable test plan
