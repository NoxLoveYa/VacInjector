# Phase 07 — Testing, Validation, Ban Triage Lab

**Goal:** Prove VacSafe without burning main accounts. Every claim gets a lab test.

## 7.1 Lab Setup
- [ ] Dedicated VM: Win11 22H2 clean snapshot, Steam + 1x throwaway account per game, no personal login, VPN isolated
- [ ] Test modes in order of risk:
  1. `notepad.exe` inject loop (no VAC)
  2. `game.exe -insecure` (VAC disabled, logic test)
  3. `game.exe` local bot server, VAC enabled, no MM (low risk)
  4. Casual/MM (high risk, throwaway only, one build per account — never reuse)
- [ ] Tooling: ProcessHacker (VAD/handles), WinDbg Preview (break on `LdrLoadDll`), ProcMon (file/reg), `gh_flag` VAD scanner, Wireshark (loader net check)

## 7.2 Test Matrix (`tests/`)
- [ ] `test_injector.cpp`: 100x inject/unload on notepad x86+x64, assert success>98%, no handle leak (`GetProcessHandleCount` delta==0)
- [ ] `test_stealth.cpp`: after inject, assert no `MZ`, no LDR entry (`LdrEnumerateLoadedModules` walk), no RWX private >64KB, startAddr spoofed
- [ ] `test_sdk.cpp`: mock `client.dll` + fake entity list, assert `WorldToScreen` math within 1px, adapter factory picks correct adapter per exe name
- [ ] `test_offsets.cpp`: validate `offsets/*.json` against current game hash, fail CI on mismatch
- [ ] Manual checklist per game: inject → ESP visible → map change → still alive → unload → re-inject → exit game clean, log attached

## 7.3 Ban Triage Protocol
- VAC bans are delayed (days/weeks) + per-account + per-build correlation. Assume any ban = build burned.
- On ban:
  1. Freeze: stop using that payload bytes + loader build everywhere, tag `BURNED-<BUILD_ID>-<date>`
  2. Diff: `git log` since last clean build, list changed sigs (new strings, imports, shellcode, hook method)
  3. Dump: save `offsets.json`, exe hash, loader log, VAD snapshot, VAC module dump if available
  4. Rotate: new BUILD_ID, re-pack with fresh junk, change IPC names + shellcode register allocation, swap method (hijack→APC or alloc→stomp)
  5. One-variable retest: only change one stealth factor per retest account, otherwise you learn nothing
- [ ] `plan/ban-log.md`: append-only, fields `date | game | BUILD_ID | method | hoursPlayed | banDelay | suspectedCause`

## Exit Criteria
- [ ] 10x clean inject/unload cycles on CS2 + TF2 `-insecure` with zero crashes, logs archived
- [ ] `gh_flag` + string scans clean on live (non-insecure) idle test
- [ ] Ban-log template created, lab accounts separated, main accounts never touched in tests
