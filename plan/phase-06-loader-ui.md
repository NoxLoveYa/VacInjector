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
- [ ] Non-dev can inject into TF2 `-insecure` in <3 clicks with zero manual PID entry
- [ ] All failure codes from Phase 03 surface as actionable UI hints (e.g., `E_ARCH_MISMATCH: use x86 payload for hl2.exe`)
- [ ] Loader binary `strings` clean: no `VacSafe`, no `cheat`, no game names plaintext
