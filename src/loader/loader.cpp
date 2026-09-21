#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "injector_core.h"

// VacSafe loader v1: Detect -> Inject -> Verify. Phase 06 full UX lands later;
// this wires the real Inject() path so notepad/game smoke actually fires.

static void Usage() {
  printf("VacSafe Injector (Phase 03 live wire)\n");
  printf("Usage: VacSafe.exe [--game cs2|tf2|css|l4d2|gmod|notepad] [--pid N] --payload payload.dll [--method auto|hijack|crt|apc] [--timeout Ms] [--verbose]\n");
  printf("Examples:\n");
  printf("  VacSafe.exe --game notepad --payload build\\x64\\src\\payload\\payload.dll --verbose\n");
  printf("  VacSafe.exe --pid 1234 --payload payload.dll --method hijack\n");
}

static std::string ArgVal(int argc, char** argv, const char* key, const char* def = "") {
  for (int i = 1; i < argc - 1; ++i)
    if (_stricmp(argv[i], key) == 0) return argv[i + 1];
  return def;
}
static bool HasFlag(int argc, char** argv, const char* key) {
  for (int i = 1; i < argc; ++i)
    if (_stricmp(argv[i], key) == 0) return true;
  return false;
}

static DWORD FindPidByExe(const char* exe) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  PROCESSENTRY32 pe{ sizeof(pe) };
  DWORD pid = 0;
  for (BOOL ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe)) {
    if (_stricmp(pe.szExeFile, exe) == 0) { pid = pe.th32ProcessID; break; }
  }
  CloseHandle(snap);
  return pid;
}

static DWORD DetectGame(const std::string& game, std::string& exeOut) {
  struct Map { const char* game; const char* exe; };
  static const Map table[] = {
    {"cs2", "cs2.exe"}, {"tf2", "tf_win64.exe"}, {"tf", "tf_win64.exe"},
    {"css", "hl2.exe"}, {"l4d2", "left4dead2.exe"}, {"gmod", "gmod.exe"},
    {"notepad", "notepad.exe"},
  };
  if (!game.empty()) {
    for (auto& m : table)
      if (_stricmp(game.c_str(), m.game) == 0) {
        exeOut = m.exe;
        DWORD pid = FindPidByExe(m.exe);
        // hl2.exe hosts multiple games; first match wins for v1 (use --pid to disambiguate).
        return pid;
      }
    return 0;
  }
  // Auto: first match in priority order.
  for (auto& m : table) {
    DWORD pid = FindPidByExe(m.exe);
    if (pid) { exeOut = m.exe; return pid; }
  }
  return 0;
}

int main(int argc, char** argv) {
  if (HasFlag(argc, argv, "--help") || HasFlag(argc, argv, "-h")) { Usage(); return 0; }

  std::string game = ArgVal(argc, argv, "--game");
  std::string pidS = ArgVal(argc, argv, "--pid");
  std::string payload = ArgVal(argc, argv, "--payload");
  std::string methodS = ArgVal(argc, argv, "--method", "auto");
  std::string timeoutS = ArgVal(argc, argv, "--timeout", "5000");
  bool verbose = HasFlag(argc, argv, "--verbose");

  DWORD pid = pidS.empty() ? 0 : (DWORD)strtoul(pidS.c_str(), nullptr, 10);
  std::string exe;
  if (!pid) {
    pid = DetectGame(game, exe);
    if (!pid) {
      printf("[fail] no target found (game='%s'). Launch notepad.exe or pass --pid.\n", game.c_str());
      Usage();
      return 1;
    }
  } else if (!game.empty()) {
    exe = game;
  }

  if (payload.empty()) {
    // Search next to exe, then default build output.
    static const char* cands[] = {
      "payload.dll", "..\\payload\\payload.dll",
      "build\\x64\\src\\payload\\payload.dll", ".\\build\\x64\\src\\payload\\payload.dll",
    };
    for (auto c : cands) {
      if (GetFileAttributesA(c) != INVALID_FILE_ATTRIBUTES) { payload = c; break; }
    }
    if (payload.empty()) {
      printf("[fail] --payload required (tried payload.dll, ..\\payload\\payload.dll, build\\x64\\src\\payload\\payload.dll).\n");
      return 1;
    }
  }

  vacsafe::InjectorConfig cfg;
  cfg.pid = pid;
  // Decode UTF-8/ANSI path to wide for CreateFileW.
  {
    int n = MultiByteToWideChar(CP_ACP, 0, payload.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> w(n);
    MultiByteToWideChar(CP_ACP, 0, payload.c_str(), -1, w.data(), n);
    cfg.payloadPath = w.data();
  }
  if (_stricmp(methodS.c_str(), "hijack") == 0) cfg.method = vacsafe::InjectorConfig::Method::ManualMapHijack;
  else if (_stricmp(methodS.c_str(), "crt") == 0 || _stricmp(methodS.c_str(), "remotethread") == 0) cfg.method = vacsafe::InjectorConfig::Method::ManualMapRemoteThread;
  else if (_stricmp(methodS.c_str(), "apc") == 0) cfg.method = vacsafe::InjectorConfig::Method::ManualMapApc;
  else cfg.method = vacsafe::InjectorConfig::Method::Auto;
  cfg.timeoutMs = timeoutS.empty() ? 5000 : (DWORD)strtoul(timeoutS.c_str(), nullptr, 10);

  if (verbose) {
    printf("[*] target pid=%lu exe='%s' payload='%s' method='%s' timeout=%lums\n",
           (unsigned long)pid, exe.c_str(), payload.c_str(), methodS.c_str(), (unsigned long)cfg.timeoutMs);
    HANDLE hProbe = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProbe) {
      PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg{};
      if (GetProcessMitigationPolicy(hProbe, ProcessDynamicCodePolicy, &acg, sizeof(acg)))
        printf("[*] ACG ProhibitDynamicCode=%d AllowThreadOptOut=%d AllowRemoteDowngrade=%d\n",
               (int)acg.ProhibitDynamicCode, (int)acg.AllowThreadOptOut, (int)acg.AllowRemoteDowngrade);
      PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
      if (GetProcessMitigationPolicy(hProbe, ProcessSignaturePolicy, &sig, sizeof(sig)))
        printf("[*] Signature mitigation=0x%lX\n", (unsigned long)sig.MicrosoftSignedOnly);
      HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
      HMODULE localK32 = GetModuleHandleW(L"kernel32.dll");
      HMODULE mods[512]; DWORD need = 0;
      HMODULE tNtdll = nullptr, tK32 = nullptr;
      if (EnumProcessModules(hProbe, mods, sizeof(mods), &need)) {
        for (DWORD i = 0; i < need / sizeof(HMODULE); ++i) {
          char nm[64] = {0};
          if (GetModuleBaseNameA(hProbe, mods[i], nm, sizeof(nm))) {
            if (_stricmp(nm, "ntdll.dll") == 0) tNtdll = mods[i];
            if (_stricmp(nm, "kernel32.dll") == 0) tK32 = mods[i];
          }
        }
      }
      printf("[*] ntdll local=%p target=%p %s | kernel32 local=%p target=%p %s\n",
             localNtdll, tNtdll, (localNtdll == tNtdll) ? "SAME" : "DIFFER",
             localK32, tK32, (localK32 == tK32) ? "SAME" : "DIFFER");
      CloseHandle(hProbe);
    }
  }

  vacsafe::InjectResult r = vacsafe::Inject(cfg);

  if (r.ok()) {
    printf("[ok] injected base=%p entryCalled=1 stealthMask=0x%X pid=%lu\n",
           r.injectedBase, r.stealthMask, (unsigned long)pid);
    return 0;
  }
  printf("[fail] ntstatus=0x%08lX base=%p entry=%d err=%s\n",
         (unsigned long)(uint32_t)r.ntstatus, r.injectedBase, (int)r.entryCalled, r.error.c_str());
  if (r.ntstatus == VACSAFE_E_ARCH_MISMATCH)
    printf("hint: E_ARCH_MISMATCH — match payload arch to target (x64 payload for cs2.exe/tf_win64.exe, x86 helper for hl2.exe x86).\n");
  else if (r.ntstatus == VACSAFE_E_EXEC_TIMEOUT)
    printf("hint: E_EXEC_TIMEOUT — DllMain did not return; try --method apc or check payload entry.\n");
  else if (r.ntstatus == VACSAFE_E_OPEN)
    printf("hint: E_OPEN — same-IL, no admin needed; close handles holding the game open.\n");
  return 1;
}
