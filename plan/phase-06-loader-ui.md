# Phase 06 — Loader + Driver + UX

**Goal:** One-click flow: pick game → spoof hygiene → inject → confirm → manage.

## 6.1 Loader App (`loader/`)
- Stack: C++ Win32 or C# WPF? Recommendation: C++ `imgui` internal panel OR minimal Win32 GUI — no Electron, no suspicious `node.dll`
- Flow:
  1. `Detect`: enumerate `CreateToolhelp32Snapshot` for known exes (`cs2.exe`, `tf_win64.exe`, `hl2.exe`, `gmod.exe`), show PID + arch + Trusted status
  2. `Prepare`: randomize IPC names, decrypt payload bytes to RAM only, `Stealth::ApplyPre`, jitter delay
  3. `Inject`: `injector-core::Inject(config)` with progress + NTSTATUS log view
  4. `Verify`: IPC `ping` → payload responds with `BUILD_ID + adapter name + entity count`; green check
  5. `Manage`: `unload`, `re-inject`, `open config`, `dump offsets`, `wipe logs`
- [ ] CLI parity: `VacSafe.exe --game cs2 --method hijack --payload payload.enc --verbose` for scripting/lab
- [ ] Config: `config.json` (game profiles, method preference, `preferStomp`, hotkeys) — encrypted at rest with DPAPI
- [ ] Self-protection: loader checks own integrity (BUILD_ID hash), refuses to run under `Wireshark/ProcMon`? No — allow lab tools, just warn. Never require admin unless driver path selected.
- [ ] No auto-elevate, no `runas` loop, no UAC bypass tricks (those burn trust + sigs)

## 6.2 Driver (optional, `driver/`)
- Only build if Phase 01 go-decision = yes. Minimal KMDF:
  - `IOCTL_VACSAFE_READ/WRITE`: `MmCopyVirtualMemory` with `PreviousMode=KernelMode`, validates caller PID + signed challenge
  - `IOCTL_VACSAFE_HIDE`: `PsSetLoadImageNotifyRoutine` strip + `LDR` unlink assist from kernel (more robust than user unlink)
  - Signed: test-sign for lab (`bcdedit /set testsigning on` VM only), never ship stolen/leaked cert. Document BYOVD risk — do NOT bundle vulnerable driver.
- [ ] `driver_client` falls back to user-mode automatically if driver not loaded; UI shows `Mode: UM / KM`

## 6.3 UX Details
- Dark theme, monospace log pane with `NTSTATUS` hex + plain English, copy-on-click error code
- First-run wizard: checks `VC++ Redist`, arch mismatch, Steam running, `-insecure` warning for testing vs live
- Kill-switch: `PANIC_KEY (END)` → IPC unload + free VAD + close handles + wipe decrypted bytes in loader RAM (`SecureZeroMemory`)

## Exit Criteria
- [x] CLI inject with zero manual PID entry (`--game cs2` auto-detects; double-click = detect + inject + pause). GUI 3-click flow deferred (CLI covers v1; game picker is cosmetic).
- [x] All failure codes surface as actionable hints (E_ARCH_MISMATCH / E_EXEC_TIMEOUT / E_OPEN) + `--verbose` mitigation/handle/base diagnostics.
- [ ] Loader binary `strings` clean: no `VacSafe`, no `cheat`, no game names plaintext — OPEN: loader keeps CLI literals + game table (not injected; file-scan surface only). Obfuscate in 06b if file-scan telemetry appears.
- [x] Driver: NO-GO v1 per `plan/kernel-decision.md` (UM-only VAC, trust-factor cost). `Mode: UM` implicit; revisit trigger documented.

## Build Notes (2026-09-21 lab)
- `--version` prints BUILD_ID (freshness proof against stale copies).
- Offsets handoff: `offsets/cs2.json` -> `%TEMP%\VacSafe-offsets.ini` (payload prefers ini).
- Post-build stages `payload.dll` + `payload.map` next to `VacSafe.exe` for double-click flow.
