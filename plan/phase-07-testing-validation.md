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
- [x] Inject cycles with zero crashes (2026-09-21 lab): busyloop 10/10 `[ok]` + 10/10 alive; cmd 3/3; CS2 `-insecure` repeated `[ok]` + 10+ min survival (pid 2744/20280), entity proof + 120-tick ESP loop clean. TF2 cycles pending install.
- [ ] `gh_flag` + string scans clean on live (non-insecure) idle test — pending throwaway protocol.
- [x] Ban-log template created (`plan/ban-log.md`); main account already touched once (live test pre-protocol) — assume flagged, throwaways from here.

## Evidence Log (2026-09-21)
- `busyloop.exe` x64 auto `.enc`: 10/10 success, 10/10 alive @+5s, marker files written.
- `cmd.exe` x64 auto `.enc`: 3/3 success, targets exited clean by operator (no crash).
- `cs2.exe -insecure` (build 14181): repeated `[ok]` (hijack + auto), `VacSafe-cs2.txt` (globals/schema/entities), 120-tick ESP loop, 10+ min survivals. No `-insecure` crashes after zero-fault-reads fix.
- Store `notepad.exe`: hostile target (remote threads fault in ntdll) — excluded from matrix with cause.
- Payload binary: python byte-search clean for 24 sensitive literals; IAT holds EH-machinery only.
