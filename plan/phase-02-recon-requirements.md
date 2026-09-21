# Phase 02 — Recon, Requirements, VAC Threat Model

**Goal:** Know exactly what we're evading before writing a line of injector code.

## 2.1 Target Enumeration
- [ ] Build target matrix: exe name, arch (x86/x64), engine (GoldSrc / Source1 / Source2), renderer (DX9/DX11/Vulkan), Trusted Mode (CS2 only), bitness of `steamservice.exe`
- [ ] For each Tier 1/2 game record:
  - Process name, AppID, module list baseline (`client.dll` / `client.so`, `engine.dll`, `schemasystem.dll` for CS2)
  - Handle rights needed for read/write, integrity level, Protected Process Light status
  - Launch flags: `-insecure`, `-allow_third_party_software` behavior for testing
- [ ] Document Steam + VAC file layout: `SteamService.dll`, `vac*.dll` streaming location, `bin/` service helpers

Deliverable: `plan/target-matrix.md` table.

## 2.2 VAC Threat Model
VAC is user-mode modular scanner streamed from backend. Assume:
- [ ] Module enumeration: PEB LDR (`InLoadOrder`, `InMemoryOrder`), `NtQueryVirtualMemory`, VAD walk
- [ ] Code scans: private RWX/RW regions, PE header magic (`MZ`), syscall stubs, hook trampolines in `gameoverlayrenderer`, `ntdll`, engine VMTs
- [ ] Handle enumeration: `NtQuerySystemInformation(SystemHandleInformation)`, open handles to game / LSASS / CSRSS
- [ ] Window/class enumeration: `FindWindow`, overlay class names, `SetWindowsHookEx` artifacts
- [ ] File + driver enumeration: known cheat driver names, service keys, MiniFilter altitudes
- [ ] Net / account telemetry: VAC bans are delayed + correlated; VAC Live (CS2) is disruptive mid-match
- [ ] Trusted Mode: CS2 blocks unsigned DLLs, `-allow_third_party_software` disables Trusted; design for Trusted-compatible path vs non-Trusted path

Study vectors (lab only, `-insecure` + local server):
- [ ] ProcMon + WinDbg + API Monitor trace of `steamservice.exe` duringTexture / module stream
- [ ] Dump streamed VAC modules to IDA/Binja, tag IOCs: `NtReadVirtualMemory`, `EnumProcessModules`, `GetMappedFileName`, `CreateToolhelp32Snapshot`, string tables
- [ ] Catalog public detection history: handle-perm flags, `ManualMap` shellcode sigs, `SetWindowDisplayAffinity` overlay tricks, `open handle 0x1FFFFF` heuristic

Deliverable: `plan/vac-threat-model.md` with scan categories + our counter per category.

## 2.3 Functional Requirements
- Universal: one injector binary auto-detects game + arch, picks adapter
- Injection latency < 5s, success rate > 98% across 100 local injects, no crash on map change
- Payload hot-unload + re-inject without game restart
- Offline mode: works with Steam offline, no network beacon from loader
- Logging: verbose local log, zero remote telemetry

## 2.4 Non-Requirements (v1)
- No kernel bypass for Vanguard/EAC/FaceIt AC — VAC only
- No ring-0 mapper v1 unless user-mode path proves insufficient for CS2 Trusted
- No auto-update cheat features (aimbot etc.) — that's payload SDK's job (Phase 05)

## Exit Criteria
- [ ] `target-matrix.md` filled for CS2 + 2x Source1 games
- [ ] `vac-threat-model.md` with ≥12 concrete scan vectors + counters
- [ ] Go/no-go on kernel component: decide in writing, with rationale
