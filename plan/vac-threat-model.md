# VAC Threat Model — Scan Vectors + Counters (Phase 02 Deliverable)

Source synthesis: `danielkrupinski/vac` (streamed module IDs), `Aspasia1337/VAC-ModuleDumper` (`steamservice.dll` + `_runfunc@20`), `jaycs1723658/cs2-vac-internals` (CS2 Trusted Launch + client.dll msgs), `danielkrupinski/cs2-anticheat` (Inventory/VMT/interface checks), `Potato-Injector` + `crvvdev/vac-bypass-kernel` (public bypass history).

VAC is user-mode, modular, server-directed. No kernel driver. Assume server correlates everything with delay; VAC Live (CS2) can disrupt mid-match.

## V01 — PEB LDR module enumeration
- What: walk `PEB_LDR_DATA` (`InLoadOrder/MemoryOrder/InitOrder` + `LdrpHashTable`), `EnumProcessModules`, `CreateToolhelp32Snapshot`, `GetMappedFileName`.
- CS2 tie: msg 159 dumps 40+ fields (loaded DLLs, PE timestamps), msg 158 module-tree CRC32 (two passes) + name/path entries at connect.
- Counter: ManualMap (never `LdrLoadDll`), `UnlinkLdr` all three lists under `LdrLockLoaderLock`, keep hash table consistent, erase headers. Verify with `LdrEnumerateLoadedModules` walk in tests.

## V02 — VAD / VirtualQuery region walk
- What: `NtQueryVirtualMemory(MemoryBasicInformation)` sweep for private `RWX`/`RX` with no file backing, large `MEM_PRIVATE` RX blobs, `MEM_IMAGE` lookalike check.
- CS2 tie: external `steam.exe` engine does `NtQueryVirtualMemory` only + 4-handle cross-reads.
- Counter: per-section protect (`RX` text, `RW` data, never `RWX`), split allocs <200KB, `preferStomp` into dead module slack (`crashhandler.dll` padding), free on unload. `gh_flag` scanner must report clean.

## V03 — PE magic + header scans
- What: `MZ`/`PE\0\0` scan on private memory, `e_lfanew`, section-name strings (`.text`, `UPX`, packer tags), `SizeOfImage` match.
- Counter: `EraseHeaders` (zero DOS+NT+sections post-entry), randomize section names pre-map, timestamp jitter per build. `strings.exe` on dump finds zero `VacSafe/payload.dll`.

## V04 — Read-only section integrity (Inventory)
- What: `client.dll!ComputeInventory2` — copy headers + every non-writable section, undo `DIR64` relocs, zero IAT+Export, CRC32 read-only (` .text/.rdata/.pdata/.reloc` hashed, `.data` skipped). Per-module PDB path + `SizeOfImage` + timestamp exfiltrated (msg 161 Scanner 1). `Plat_RegisterModule/Plat_GetRegisteredModules` list is ground truth.
- Counter: never patch game `.text` read-only, never inline `0xE9` on engine. For ESP use shadow VMT copy + pointer swap, restore on unload. Payload lives in own private alloc, not as registered module edit.

## V05 — Interface + VMT frequency checks
- What: msg 161 Scanner 2/3 — engine VMT pointer frequency map, 112 interface CRCs (`CreateInterface` versions `VClient*`, `VEngineClient*`, `SchemaSystem_001`), global interface VMT snapshot. Any hook changes frequency/outlier.
- Counter: shadow VMT, single pointer swap, no `FF25` hook scan surface beyond one slot, no `ntdll` hooks. Hook `Present` (DX11/Vulkan `vkQueuePresentKHR`) not engine VMT where possible.

## V06 — External cross-process reads
- What: `steam.exe`/`SteamService.exe` `NtReadVirtualMemory` sweeps of game memory, 4 handles cross-verification to defeat single-handle spoof. Legacy modules ID 2/3: process/handle list + `VacProcessMonitor` filemapping.
- Counter: no `PROCESS_ALL_ACCESS` handle from loader (minimal rights, close immediately), payload does internal deref + SEH guard (no `ReadProcessMemory`), no filemapping, no named objects with cheat names. Kernel spoof (SSDT/InfinityHook) explicitly deferred — see kernel decision.

## V07 — Handle enumeration
- What: `NtQuerySystemInformation(SystemHandleInformation)`, `GetProcessImageFileNameA` last-36-chars check, handle perm heuristic (`0x1FFFFF` = flag), LSASS/CSRSS opens.
- Counter: minimal-rights open, `NtDuplicateObject` blend where useful, close post-inject, handle-count delta 0 in tests. Loader never holds game handle idle.

## V08 — Trusted Launch catalog gate (CS2 pre-engine)
- What: `cs2.exe` pre-`engine2.dll`: 4 catalogs via `CryptCatAdminAcquireContext2`, `NtOpenFile` hook (`DesiredAccess & 0x21` → sig check → `0xC0000034` on unsigned), VEH registered, `-insecure` skips all.
- Counter: two paths — Trusted-compatible (no unsigned file open with `RX` intent, payload via private anon alloc only, no disk DLL) vs non-Trusted (`-allow_third_party_software` documented for testing). Never drop unsigned `.dll` to game dir.

## V09 — Server-directed interrogation (msg 162 S→C)
- What: on-demand DR dump / memory read / export probe / code exec. Server can ask client to dump bytes, probe export, or run snippet.
- Counter: payload exports nothing (`GetProcAddress` on payload fails), no RWX to dump meaningfully, exception+VEH hygiene (next), offline payload (no socket). Assume any answer is logged server-side — minimize answerable surface.

## V10 — Debug register + VEH + exception telemetry
- What: msg 163 (~5s + on-demand): DR0-3 registers, VEH chain (10 handlers), 64×2944B exception stack dumps. Msg 164: unknown-module return addresses, data-hash mismatches. `IsDebuggerPresent`, `BSecureAllowed`, CPUID, cmdline in msg 159.
- Counter: `ThreadHideFromDebugger` on payload threads, no INT3/DR usage, register our VEH last and chain cleanly, no `g_pNetworkChannel` tampering, no cmdline spoof. Crash guard via `__try/__except` without leaving VEH residue.

## V11 — Window / overlay / hook artifacts
- What: `FindWindow`/class enumeration, `SetWindowsHookEx` residue, external `Topmost+Transparent+LWA` overlay, `SetWindowDisplayAffinity` trick, `gameoverlayrenderer` trampoline check (first 8B snapshot on `NtOpenFile`/`LoadLibraryExW` + suspicious threads).
- Counter: internal `Present` hook render only, no external overlay window, no `SetWindowsHookEx`, no `gameoverlayrenderer` patch. Loader window title/metadata mimic generic host, random IPC names per boot.

## V12 — File / driver / service enumeration
- What: known driver names, service keys, MiniFilter altitudes, `NtQuerySystemInformation` for Test/Debug mode (trust-factor signal), `GetSystemDirectoryW` + `ntdll.dll` on-disk processing (hook detect on `VacProcessMonitor`).
- Counter: v1 ships no driver (see decision), no service, no filter. Test-sign VM only for lab. Never bundle vulnerable driver (BYOVD burns trust). No `bcdedit testsigning` requirement on user machine.

## V13 — String / import / shellcode signatures
- What: streamed-module string tables historically (`NtReadVirtualMemory`, `EnumProcessModules`, `CreateToolhelp32Snapshot` literals), `ManualMap` shellcode sigs (<512B stubs with fixed prologues), IAT literals (`LoadLibraryA`, `CreateRemoteThread`).
- Counter: `VACSAFE_OBF()` stack-only decrypt, import-by-hash via PEB walk (no IAT for `Nt*`/`ReadProcessMemory`/`DeviceIoControl`), per-build shellcode register reallocation + junk, `pack_payload.py` ChaCha20 + junk sections. `hash_imports.py` CI gate bans `LoadLibraryA/CreateRemoteThread/SetWindowsHookEx` literals.

## V14 — Account / network correlation + VAC Live
- What: delayed bans (days/weeks), per-account + per-build correlation, CRC unique per SteamID historically, VAC Live mid-match disruption in CS2, counter-strafe telemetry (msg 385) + convar checks (`CUserMessageRequestUtilAction`).
- Counter: one BUILD_ID per account set, never reuse bytes after ban (`BURNED-<ID>`), loader HTTPS version check with generic UA only, payload zero sockets, features default OFF, no convar tampering in v1. `plan/ban-log.md` append-only (`date|game|BUILD_ID|method|hours|delay|suspectedCause`).

## Lab Study Vectors (to confirm above)
- ProcMon `%TEMP%` + WinDbg `bp steamservice!ExecVacModule` + API Monitor on `SteamService.exe` during MM connect (expect few/no streamed modules now — document negative result too).
- Binja dump of `steamservice.dll` + `client.dll`: tag `NtReadVirtualMemory`, `NtQueryVirtualMemory`, `EnumProcessModules`, `GetMappedFileName`, `_runfunc@20`, `ComputeInventory2`, `Plat_RegisterModule`, protobuf `CUserMessage_*` handlers.
- History catalog: `0x1FFFFF` handle heuristic, BlackBone `mmap().MapImage` sig, `vac3_bypass.hpp` bytecode reuse risk, SSDT vs InfinityHook tradeoffs for future KM path.
