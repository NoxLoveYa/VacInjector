# Phase 03 — Injection Core

**Goal:** Reliable, artifact-free DLL injection supporting every VAC game arch.

## 3.1 Methods to Implement (in order)
1. **ManualMap v1 (default, user-mode):**
   - Parse PE in loader, allocate `MEM_COMMIT|RESERVE, PAGE_READWRITE` in target via `NtAllocateVirtualMemory` with spoofed handle
   - Copy headers + sections, apply relocs (`IMAGE_REL_BASED_DIR64/HIGHLOW`), resolve imports by hash (`ntdll!LdrLoadDll` hash, not `LoadLibraryA` string)
   - Fix `Protect` per-section (`RX` for `.text`, `RW` for `.data`), then erase DOS header + `e_lfanew` + section names post-call
   - Call entry via hijacked thread (see below), NOT `CreateRemoteThread`
2. **Thread Hijack (execution):**
   - `NtGetNextThread` / suspend existing game thread (e.g., sound or worker thread, never main render thread)
   - `GetThreadContext/SetThreadContext` to RIP-redirect to shellcode stub, restore on completion with event sync
   - Shellcode: position-independent, <512B, calls `DllMain(DLL_PROCESS_ATTACH)`, signals completion, returns to original RIP
3. **APC Queue (fallback):**
   - `QueueUserAPC` to alertable thread for games where hijack is flaky (GMod Lua threads)
4. **Kernel Map (optional, gated):**
   - Driver `MmCopyVirtualMemory` + `KeStackAttachProcess` manual map, PTE `NX` handling, no user-mode handle at all
   - Only if CS2 Trusted blocks all user paths in testing

Explicitly BANNED: `CreateRemoteThread + LoadLibraryA/W`, `SetWindowsHookEx`, raw `WriteProcessMemory` of full plaintext DLL without encryption.

## 3.2 Handle Hygiene (injector-side)
- [ ] Open game with minimal rights: `PROCESS_VM_OPERATION|VM_WRITE|VM_READ|QUERY_INFORMATION|CREATE_THREAD|SUSPEND_RESUME` — never `PROCESS_ALL_ACCESS`
- [ ] Use `NtDuplicateObject` from `steam.exe` handle if available to blend parent, or `NtOpenProcess` with `OBJ_CASE_INSENSITIVE`
- [ ] Close handle immediately post-inject, zero `HANDLE` in loader memory, no handle leak on failure path
- [ ] WoW64 bridge: x64 loader spawns suspended `x86` helper for x86 games, IPCs payload bytes, helper does inject then exits

## 3.3 Tasks
- [ ] `injector-core/manual_map.{h,cpp}`: PE parser, reloc, import resolver (hash-based), section protect
- [ ] `injector-core/thread_hijack.{h,cpp}` + `shellcode/x64_stub.asm`, `x86_stub.asm`
- [ ] `injector-core/apc.{h,cpp}`
- [ ] `injector-core/driver_client.{h,cpp}` (stub if no driver yet)
- [ ] `injector-core/dispatch.cpp`: `Inject(config) -> InjectResult`, auto-picks method by arch + game flags + retry logic (hijack -> APC -> fail cleanly)
- [ ] Unit tests with mock process (notepad.exe): 100x inject/unload loop, no crash, no leak (checked via `!htrace`)

## 3.4 Failure Handling
- Timeout on entry (5s), `NtFreeVirtualMemory` cleanup, thread resume guaranteed via RAII guard
- Error codes: `VACSAFE_E_OPEN(0x100)`, `E_ALLOC`, `E_RELOC`, `E_IMPORT`, `E_EXEC_TIMEOUT`, `E_ARCH_MISMATCH` — surfaced to loader UI, logged with NTSTATUS hex

## Exit Criteria
- [x] ManualMap + Hijack proven on classic Win32 (`busyloop.exe` runner + `cmd.exe` waiter): `[ok] entryCalled=1 stealthMask=0x7`, target survives, re-injectable. `cs2.exe -insecure` + `tf_win64.exe -insecure` pending game install.
- [ ] No `MZ` header, no LDR entry, no RWX after `ApplyPost` (partial: RX/RW verified via VirtualQueryEx trace; header-erase+LDR-unlink land in Phase 04)
- [ ] Wireshark/ProcMon shows no `LoadLibrary` string or plaintext DLL bytes on disk

## Build Notes (2026-09-21 lab)
- Raw `DllMain` via `payload.map` (` DllMain ` -> section VA + off) is the execution target. `DllMainCRTStartup` hangs on hijacked foreign threads (loader-lock/TLS path); fresh CRT threads are unaffected. MAP fallback = PE entry.
- Dispatch order `auto` = hijack (v4 hunt: set-ctx, 30ms stick check, 1200ms flag poll, restore) -> remote-thread (fresh OS thread, `RtlExitUserThread`, no LoadLibrary) -> APC.
- `VirtualProtect` is page-granular: stub and flag/scratch MUST live on separate pages or the flag write AVs. Same bug class fixed in hijack + APC stubs.
- Win11 Store `notepad.exe` (`Microsoft.WindowsNotepad_*`, AppContainer) is NOT a valid lab target: remote threads fault inside `ntdll.dll` (WER: `c0000005` at `ntdll+0x5BE6B`) despite clean mapping, same module bases, no ACG. Games are classic Win32 — validate on `busyloop.exe`/`cmd.exe`/games, not Store apps.
- Diag env gates (dev only): `VACSAFE_VERBOSE=1`, `VACSAFE_NOCALL=1` (hijack mechanics probe), `VACSAFE_CRTNOCALL=1`.
- RAW-ENTRY LAW (proven 2026-09-21): payload code on the raw-`DllMain` path must be kernel32-only. No CRT printf-family/`strlen`/`snprintf`/locale/errno: UCRT per-thread data is never initialized when CRT startup is bypassed, first such call AVs (`0xC0000005`) even on fresh threads. `Beep`/`OutputDebugStringA`/file APIs are safe. Phase 05 SDK must respect this (heap + SSO strings OK, formatted I/O forbidden) or run CRT entry on fresh threads only.
