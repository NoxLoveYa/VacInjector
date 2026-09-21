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
- [ ] ManualMap + Hijack works on `notepad x64/x86` + `cs2.exe -insecure` + `tf_win64.exe -insecure`
- [ ] No `MZ` header, no LDR entry, no RWX after `ApplyPost` (verified with ProcessHacker VAD view)
- [ ] Wireshark/ProcMon shows no `LoadLibrary` string or plaintext DLL bytes on disk
