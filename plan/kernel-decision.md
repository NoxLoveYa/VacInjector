# Kernel Go / No-Go — Phase 02 Decision

**Decision: NO-GO for v1. User-mode only.**

## Rationale
1. VAC is pure user-mode (`NtReadVirtualMemory` + `NtQueryVirtualMemory` external + `client.dll` in-process). No kernel component to fight, so kernel buys little.
2. CS2 Trusted Launch is beaten with private anon alloc + no unsigned `NtOpenFile(RX)` — no driver needed. Non-Trusted path covers testing.
3. Kernel costs outweigh gains v1: DSE/PG bypass (EfiGuard/test-sign) burns trust-factor (`NtQuerySystemInformation` Test/Debug checks), BYOVD/stolen cert = instant mass-ban correlation, MiniFilter/service enumeration is itself a scan vector (V12).
4. Public KM bypasses (`SSDT` not PG-compatible, `InfinityHook` version-fragile) need per-Windows-build maintenance — wrong scope for universal VAC injector v1.
5. UM path not yet exhausted: ManualMap + hijack + `EraseHeaders/UnlinkLdr/SpoofStart` + shadow VMT + stomp option covers V01-V14 above on paper.

## Trigger to Revisit
- UM blocked reproducibly: Trusted `NtOpenFile` gate or external 4-handle reads flag private RX even with stomp + split allocs across 3+ lab builds, with VAD dumps attached.
- Then: minimal KM assist only (`MmCopyVirtualMemory` READ/WRITE + hide assist, no SSDT hooks), test-sign lab VM, `driver_client` already stubbed for fallback. No file filter, no process protection.

## Action
- `VACSAFE_BUILD_DRIVER OFF` default. `src/driver/` stays stub. Loader shows `Mode: UM`.
- Re-evaluate after Phase 07 live-idle tests on CS2 + TF2-x64.
