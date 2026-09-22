#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "injector_core.h"
#include "nt_api.h"
#if __has_include("build_id.h")
#include "build_id.h"
#endif
#ifdef VACSAFE_BUILD_ID
#define VACSAFE_BIDSTR VACSAFE_BUILD_ID
#else
#define VACSAFE_BIDSTR "nobid-run-gen_build_id"
#endif

// VacSafe loader v1: Detect -> Inject -> Verify. Phase 06 full UX lands later;
// this wires the real Inject() path so notepad/game smoke actually fires.

static void Usage() {
  printf("VacSafe Injector (Phase 03 live wire)\n");
  printf("Usage: VacSafe.exe [--game cs2|tf2|css|l4d2|gmod|notepad] [--pid N] --payload payload.dll [--method auto|hijack|crt|apc] [--timeout Ms] [--verbose]\n");
  printf("Double-click (no args): auto-detects game, injects payload.dll next to the exe, pauses.\n");
  printf("Examples:\n");
  printf("  VacSafe.exe --game notepad --payload build\\x64\\src\\payload\\payload.dll --verbose\n");
  printf("  VacSafe.exe --pid 1234 --payload payload.dll --method hijack\n");
}

// Double-click runs with argc==1 and the window would vanish on exit: pause instead.
static void MaybePause(bool pause) {
  if (!pause) return;
  printf("\n[press Enter to close]");
  fflush(stdout);
  getchar();
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
  const bool pauseAtEnd = (argc == 1); // double-clicked: keep window open
  printf("[VacSafe build %s]\n", VACSAFE_BIDSTR);
  if (HasFlag(argc, argv, "--help") || HasFlag(argc, argv, "-h")) { Usage(); MaybePause(pauseAtEnd); return 0; }
  if (HasFlag(argc, argv, "--version") || HasFlag(argc, argv, "-v")) { printf("VacSafe %s\n", VACSAFE_BIDSTR); MaybePause(pauseAtEnd); return 0; }
  if (HasFlag(argc, argv, "--selftest")) {
    // Resolve every hashed API the payload needs, in THIS process. Same code (nt_api).
    struct T { const wchar_t* mod; uint32_t h; const char* name; };
    static const T tests[] = {
      {L"kernel32.dll", 0x7C82FBA1, "Beep"}, {L"kernel32.dll", 0x9EF979E9, "GetTempPathA"},
      {L"kernel32.dll", 0xEB96C5FA, "CreateFileA"}, {L"kernel32.dll", 0x663CECB0, "WriteFile"},
      {L"kernel32.dll", 0x3870CA07, "CloseHandle"}, {L"kernel32.dll", 0x530574F5, "DisableThreadLibraryCalls"},
      {L"kernel32.dll", 0x79729F95, "OutputDebugStringA"}, {L"kernel32.dll", 0x7F08F451, "CreateThread"},
      {L"kernel32.dll", 0x13B8A14D, "GetModuleFileNameA"}, {L"kernel32.dll", 0x0E19E5FE, "Sleep"},
      {L"kernel32.dll", 0x71019921, "ReadFile"}, {L"kernel32.dll", 0x7891C520, "GetFileSize"},
      {L"user32.dll", 0xA988C1A1, "GetSystemMetrics(user32)"},
    };
    int fails = 0;
    for (auto& t : tests) {
      void* p = vacsafe::nt::GetProcByHash(t.mod, t.h);
      printf("[%s] %-32s %p\n", p ? "ok" : "FAIL", t.name, p);
      if (!p) ++fails;
    }
    printf("selftest: %s\n", fails ? "FAIL" : "ALL OK");
    return fails ? 1 : 0;
  }

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
      MaybePause(pauseAtEnd);
      return 1;
    }
  } else if (!game.empty()) {
    exe = game;
  }

  if (payload.empty()) {
    // Prefer encrypted (.enc, newest first), fall back to plain DLL.
    // Double-click (CWD = exe dir) resolves to the staged/post-build outputs.
    static const char* encDirs[] = { ".\\", "..\\..\\" };
    std::string bestEnc;
    FILETIME bestTime{};
    for (auto d : encDirs) {
      std::string pat = std::string(d) + "payload-*.enc";
      WIN32_FIND_DATAA fd{};
      HANDLE h = FindFirstFileA(pat.c_str(), &fd);
      if (h == INVALID_HANDLE_VALUE) continue;
      do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
          std::string full = std::string(d) + fd.cFileName;
          if (CompareFileTime(&fd.ftLastWriteTime, &bestTime) > 0) {
            bestTime = fd.ftLastWriteTime;
            bestEnc = full;
          }
        }
      } while (FindNextFileA(h, &fd));
      FindClose(h);
    }
    // Legacy dev name also honored (repacked by hand).
    for (auto c : { ".\\payload-test.enc", "..\\..\\payload-test.enc" }) {
      if (GetFileAttributesA(c) == INVALID_FILE_ATTRIBUTES) continue;
      WIN32_FILE_ATTRIBUTE_DATA fa{};
      if (GetFileAttributesExA(c, GetFileExInfoStandard, &fa) &&
          CompareFileTime(&fa.ftLastWriteTime, &bestTime) > 0) {
        bestTime = fa.ftLastWriteTime;
        bestEnc = c;
      }
    }
    if (!bestEnc.empty()) {
      payload = bestEnc;
    } else {
      static const char* cands[] = {
        "payload.dll", "..\\payload\\payload.dll",
        "build\\x64\\src\\payload\\payload.dll", ".\\build\\x64\\src\\payload\\payload.dll",
      };
      for (auto c : cands) {
        if (GetFileAttributesA(c) != INVALID_FILE_ATTRIBUTES) { payload = c; break; }
      }
    }
    if (payload.empty()) {
      printf("[fail] --payload required (no payload-*.enc and no payload.dll found).\n");
      MaybePause(pauseAtEnd);
      return 1;
    }
    printf("[*] payload: %s\n", payload.c_str());
  }

  // Offsets handoff: offsets/cs2.json -> %TEMP%\VacSafe-offsets.ini (payload prefers it).
  // Minimal parse: "dwEntityList": <dec>, no JSON lib. Missing file = scan path.
  {
    const char* jcands[] = {
      "src\\payload\\offsets\\cs2.json", "..\\..\\src\\payload\\offsets\\cs2.json",
      "build\\..\\src\\payload\\offsets\\cs2.json", ".\\src\\payload\\offsets\\cs2.json",
      "..\\..\\..\\..\\src\\payload\\offsets\\cs2.json", // loader-dir deep builds
    };
    std::string jpath;
    for (auto c : jcands) {
      if (GetFileAttributesA(c) != INVALID_FILE_ATTRIBUTES) { jpath = c; break; }
    }
    // Also try next to the loader exe (repo-root runs).
    char exeDir[MAX_PATH] = {0};
    if (jpath.empty() && GetModuleFileNameA(nullptr, exeDir, sizeof(exeDir))) {
      std::string d = exeDir;
      auto p = d.find_last_of("\\/");
      if (p != std::string::npos) {
        std::string t = d.substr(0, p + 1) + "..\\..\\src\\payload\\offsets\\cs2.json";
        if (GetFileAttributesA(t.c_str()) != INVALID_FILE_ATTRIBUTES) jpath = t;
      }
    }
    if (!jpath.empty()) {
      FILE* jf = nullptr;
      if (fopen_s(&jf, jpath.c_str(), "r") == 0 && jf) {
        fseek(jf, 0, SEEK_END);
        long jsz = ftell(jf);
        fseek(jf, 0, SEEK_SET);
        std::string js;
        if (jsz > 0 && jsz < 8192) { js.resize((size_t)jsz); fread(js.data(), 1, (size_t)jsz, jf); }
        fclose(jf);
        auto grab = [&](const char* key) -> uint32_t {
          auto at = js.find(key);
          if (at == std::string::npos) return 0;
          at = js.find(':', at);
          if (at == std::string::npos) return 0;
          return (uint32_t)strtoul(js.c_str() + at + 1, nullptr, 10);
        };
        uint32_t e = grab("\"dwEntityList\"");
        uint32_t l = grab("\"dwLocalPlayerPawn\"");
        uint32_t v = grab("\"dwViewMatrix\"");
        if (e || l || v) {
          char tmp[MAX_PATH] = {0};
          if (GetTempPathA(sizeof(tmp), tmp)) {
            std::string ini = std::string(tmp) + "VacSafe-offsets.ini";
            FILE* of = nullptr;
            if (fopen_s(&of, ini.c_str(), "w") == 0 && of) {
              if (e) fprintf(of, "entityList=%X\n", e);
              if (l) fprintf(of, "localPlayer=%X\n", l);
              if (v) fprintf(of, "viewMatrix=%X\n", v);
              fclose(of);
              if (verbose) printf("[*] offsets ini: e=%X l=%X v=%X -> %s\n", e, l, v, ini.c_str());
            }
          }
        } else if (verbose) {
          printf("[*] offsets json has no usable values, scan path\n");
        }
      }
    } else if (verbose) {
      printf("[*] no offsets/cs2.json found, scan path\n");
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
    Beep(880, 200); // audible proof, loader-side (safe: own process/thread)
    // Mirror payload proof files: init trail, game proof, ESP snapshot, heartbeat.
    Sleep(3500); // let InitThread finish init+proof (ESP keeps ticking after)
    static const char* kProofFiles[] = {
      "VacSafe-smoke.txt", "VacSafe-init.txt", "VacSafe-cs2.txt",
      "VacSafe-dbg.txt", "VacSafe-esp.txt",
    };
    char tmp[MAX_PATH] = {0};
    if (GetTempPathA(sizeof(tmp), tmp)) {
      for (auto rel : kProofFiles) {
        std::string path = std::string(tmp) + rel;
        FILE* f = nullptr;
        if (fopen_s(&f, path.c_str(), "r") != 0 || !f) continue;
        printf("--- %s ---\n", rel);
        char line[512];
        int shown = 0;
        while (fgets(line, sizeof(line), f) && shown < 18) {
          fputs(line, stdout);
          if (line[0] && line[strlen(line) - 1] != '\n') printf("\n");
          ++shown;
        }
        fclose(f);
      }
    }
    MaybePause(pauseAtEnd);
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
  MaybePause(pauseAtEnd);
  return 1;
}
