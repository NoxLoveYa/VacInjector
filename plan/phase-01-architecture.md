# Phase 01 — Architecture & Repo Scaffold

**Goal:** Freeze component boundaries so injection, stealth, payload, and loader can evolve independently.

## 1.1 Component Map
```
[loader.exe] --(IPC/named pipe)--\
                                  >--[injector-core.dll/lib]--(ManualMap/Hijack/APC)--> [game.exe + payload.dll]
[driver.sys] --(IOCTL)--/                    ^
      |                                      |
      +--- handle spoof, VAD spoof, stealth ops
[sdk/] provides unified API consumed by payload.dll game adapters
```

- `common/`: NT API wrappers, string obfuscation, FNV1a/Murmur hashing, LZMA payload packer, config parser
- `injector-core/`: pure injection, no game logic, no rendering
- `stealth/`: static lib linked into both loader and payload (pre + post inject hygiene)
- `sdk/ + payload/`: game-agnostic cheat surface, per-engine adapters
- `loader/`: UX + orchestration only, never touches game memory directly except via injector-core
- `driver/` (optional, gated by Phase 01 decision): `\\.\VacSafe` device, IOCTLs for `READ/WRITE/HIDE/MAP`

## 1.2 ABI Contracts (freeze early)
- [ ] `InjectorConfig` struct: pid, arch, method enum, payload path/bytes, flags (eraseHeaders, unlinkLdr, spoofStartAddr, delayMs), timeout
- [ ] `InjectResult` struct: NTSTATUS, injectedBase, entryCalled, stealthApplied bitmask, error string
- [ ] `Sdk::IGameAdapter` interface: `Init()`, `GetLocalPlayer()`, `GetEntities()`, `WorldToScreen()`, `GetViewMatrix()`, `PresentHookPoint()`
- [ ] `Stealth::ApplyPre/Post` functions: callable from loader pre-inject and payload `DllMain` post-inject
- [ ] IPC protocol v1: JSON over named pipe `\\.\pipe\VacSafe-{rand}` with challenge-response, no hardcoded pipe name

## 1.3 Tech Choices
- Language: C++20 (core/sdk/loader), C (driver), Python (tools/build scripts)
- Build: CMake 3.27+ + Ninja, vcpkg for `imgui`, `minhook` (vendored, renamed), `nlohmann_json`
- Arch: compile `x86` + `x64` loader + payload; injector-core dual-arch with WoW64 bridge (`Heaven's Gate` avoided — use helper x86 process instead)
- Crypto: payload encrypted at rest (ChaCha20 + per-build key), decrypted only in loader memory, never written to disk plaintext
- Obfuscation hooks:预留 macro `VACSAFE_OBF(str)` + import hashing via `GetProcAddress(HASH)` not IAT strings

## 1.4 Repo Tasks
- [ ] `CMakeLists.txt` root with options: `VACSAFE_BUILD_DRIVER`, `VACSAFE_BUILD_TESTS`, `VACSAFE_ARCH`
- [ ] `.gitignore`: `build/`, `*.sys`, `*.pdb`, dumped VAC modules, test accounts
- [ ] `tools/` stubs: `hash_imports.py`, `pack_payload.py`, `gen_build_id.py`
- [ ] CI stub: `build.bat` / `build.sh` doing clean configure + build x86+x64

## Exit Criteria
- [ ] Clean build of empty stubs for all components x86+x64 with zero warnings at `/W4`
- [ ] Header-only `IGameAdapter` compiles against mock adapter
- [ ] No game-specific `#ifdef` outside `payload/adapters/` — enforced by code review
