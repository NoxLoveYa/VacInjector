# VacSafe Injector — Master Plan

Universal injector + payload platform for VAC-protected games.
Goal: one loader, one stealth core, per-game adapters.

## Targets (VAC games matrix)
- Tier 1: Counter-Strike 2 (Source 2, x64, Trusted Mode + VAC Live)
- Tier 2: Team Fortress 2, Counter-Strike: Source, Left 4 Dead 2, Garry's Mod (Source 1, x86/x64 mix)
- Tier 3: Generic VAC: Day of Defeat:S, Half-Life 2:DM, etc. via engine abstraction

## Phase Index
- `phase-01-architecture.md` — Repo layout, component boundaries, ABI contracts [DONE - scaffolded]
- `phase-02-recon-requirements.md` — Target enumeration, VAC threat model, requirements [NEXT]
- `phase-03-injection-core.md` — Injection primitives (user-mode + kernel-mode paths)
- `phase-04-vac-evasion.md` — Stealth, anti-scan, anti-enumeration, hygiene
- `phase-05-payload-sdk.md` — Universal game-agnostic cheat SDK
- `phase-06-loader-ui.md` — Loader app, driver service, UX flow
- `phase-07-testing-validation.md` — Lab, detection testing, ban triage
- `phase-08-build-release-ops.md` — Build, polymorphism, updates, ops

## Execution Order
01 scaffold done -> 02 recon -> 03 + 04 in parallel -> 05 -> 06 -> 07 -> 08
`src/` scaffold exists per Phase 01. No logic until Phase 02 exit criteria are met.

## Definition of VacSafe
1. No `CreateRemoteThread + LoadLibrary` artifacts
2. No RWX private image, no linked LDR entry, no PE headers in memory
3. No open HANDLE with `PROCESS_ALL_ACCESS` to game from loader
4. No known overlay / window class / string signatures
5. Payload survives `VAC module streaming` + map change + Trusted Mode checks (CS2)
6. Per-build polymorphism: rebuild == new signatures

## Repo Target (Phase 01 done)
```
plan/
src/
  injector-core/   # injection primitives
  stealth/         # evasion lib
  sdk/             # universal payload SDK
  payload/         # generic DLL payload, game adapters
  loader/          # GUI/CLI loader
  driver/          # optional kernel component
  common/          # shared utils, crypto, IPC
tests/
tools/
build/
```
