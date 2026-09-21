#include "injector_core.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace vacsafe {

HANDLE OpenGameMinimal(DWORD pid, std::string& err) {
  HANDLE h = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                         PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
                         PROCESS_SUSPEND_RESUME, FALSE, pid);
  if (!h) {
    char b[128]; snprintf(b, sizeof(b), "OpenProcess failed (GLE=0x%08lX, E_OPEN: run same-IL, no admin needed)", GetLastError());
    err = b; return nullptr;
  }
  return h;
}

static void* RemoteEntry(const uint8_t* localImg, void* base) {
  auto* dos = (IMAGE_DOS_HEADER*)localImg;
  auto* nt32 = (IMAGE_NT_HEADERS32*)(localImg + dos->e_lfanew);
  DWORD ep = (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    ? ((IMAGE_NT_HEADERS64*)nt32)->OptionalHeader.AddressOfEntryPoint
    : nt32->OptionalHeader.AddressOfEntryPoint;
  if (!ep) return nullptr;
  return (uint8_t*)base + ep;
}

// Raw user DllMain (skips DllMainCRTStartup: its loader-lock/TLS path hangs on
// hijacked foreign threads; fresh CRT threads are unaffected). Resolved from the
// linker .map next to the payload: " 0001:0000133c  _DllMain@12" -> section[0].VA + off.
static void* RemoteRawDllMain(const uint8_t* localImg, size_t imgSize, const std::wstring& payloadPath, void* base) {
  if (payloadPath.size() < 5) return nullptr;
  std::wstring mapPath = payloadPath.substr(0, payloadPath.size() - 4) + L".map";
  FILE* f = nullptr;
  if (_wfopen_s(&f, mapPath.c_str(), L"r") != 0 || !f) return nullptr;
  unsigned seg = 0, off = 0;
  char line[512];
  bool found = false;
  while (fgets(line, sizeof(line), f)) {
    if (!strstr(line, "DllMain@12") && !strstr(line, " DllMain ")) continue;
    if (sscanf_s(line, " %x:%x", &seg, &off) == 2) { found = true; break; }
  }
  fclose(f);
  if (!found || !seg) return nullptr;
  auto* dos = (IMAGE_DOS_HEADER*)localImg;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
  auto* nt32 = (IMAGE_NT_HEADERS32*)(localImg + dos->e_lfanew);
  if (nt32->Signature != IMAGE_NT_SIGNATURE) return nullptr;
  WORD nSects = nt32->FileHeader.NumberOfSections;
  if (seg < 1 || seg > nSects) return nullptr;
  IMAGE_SECTION_HEADER* sects = nullptr;
  if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    sects = IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS64*)nt32);
  else
    sects = IMAGE_FIRST_SECTION(nt32);
  (void)imgSize;
  DWORD rva = sects[seg - 1].VirtualAddress + off;
  if (!rva) return nullptr;
  return (uint8_t*)base + rva;
}

InjectResult Inject(const InjectorConfig& cfg) {
  InjectResult r;
  if (!cfg.pid) { r.error = "no pid"; r.ntstatus = VACSAFE_E_OPEN; return r; }

  std::vector<uint8_t> img;
  if (!cfg.payloadPath.empty()) {
    HANDLE f = CreateFileW(cfg.payloadPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) { r.error = "payload open failed"; r.ntstatus = VACSAFE_E_OPEN; return r; }
    DWORD hi = 0, lo = GetFileSize(f, &hi);
    uint64_t sz = ((uint64_t)hi << 32) | lo;
    if (!sz || sz > 64 * 1024 * 1024) { CloseHandle(f); r.error = "payload size bad"; r.ntstatus = VACSAFE_E_OPEN; return r; }
    img.resize((size_t)sz);
    DWORD rd = 0; ReadFile(f, img.data(), (DWORD)img.size(), &rd, nullptr);
    CloseHandle(f);
    if (rd != img.size()) { r.error = "payload read short"; r.ntstatus = VACSAFE_E_OPEN; return r; }
  } else { r.error = "no payload (set payloadPath)"; r.ntstatus = VACSAFE_E_OPEN; return r; }

  std::string e;
  HANDLE hProc = OpenGameMinimal(cfg.pid, e);
  if (!hProc) { r.error = e; r.ntstatus = VACSAFE_E_OPEN; return r; }

  BOOL wow = FALSE; IsWow64Process(hProc, &wow);
#if defined(_WIN64)
  bool t64 = !wow;
#else
  if (!wow) { r.error = "x86 loader -> x64 target (E_ARCH_MISMATCH)"; r.ntstatus = VACSAFE_E_ARCH_MISMATCH; CloseHandle(hProc); return r; }
  bool t64 = false;
#endif
  auto* dos = (IMAGE_DOS_HEADER*)img.data();
  bool img64 = false;
  if (img.size() > (size_t)dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) {
    auto* nt = (IMAGE_NT_HEADERS32*)(img.data() + dos->e_lfanew);
    img64 = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
  }
#if defined(_WIN64)
  if (img64 != t64) {
    r.error = t64 ? "x64 target needs x64 payload (E_ARCH_MISMATCH)" : "x86 target needs x86 helper + x86 payload (E_ARCH_MISMATCH)";
    r.ntstatus = VACSAFE_E_ARCH_MISMATCH; CloseHandle(hProc); return r;
  }
#endif

  void* base = ManualMap(hProc, img.data(), img.size(), e);
  if (!base) { r.error = "ManualMap: " + e; r.ntstatus = VACSAFE_E_ALLOC; CloseHandle(hProc); return r; }
  r.injectedBase = base;

  void* entry = RemoteRawDllMain(img.data(), img.size(), cfg.payloadPath, base);
  bool rawEntry = (entry != nullptr);
  if (!entry) entry = RemoteEntry(img.data(), base);
  if (!entry) { r.error = "no entry point (DLL needs DllMain)"; r.ntstatus = VACSAFE_E_IMPORT; VirtualFreeEx(hProc, base, 0, MEM_RELEASE); CloseHandle(hProc); return r; }
  if (getenv("VACSAFE_VERBOSE")) printf("[inject] entry=%p (%s)\n", entry, rawEntry ? "raw DllMain" : "CRT entry fallback");

  bool called = false;
  auto method = cfg.method;
  if (method == InjectorConfig::Method::Auto || method == InjectorConfig::Method::ManualMapHijack) {
    if (ExecViaHijack(hProc, entry, base, cfg.timeoutMs, e)) called = true;
    else if (method != InjectorConfig::Method::Auto) { r.error = "Hijack: " + e; r.ntstatus = VACSAFE_E_EXEC_TIMEOUT; }
  }
  if (!called && (method == InjectorConfig::Method::Auto || method == InjectorConfig::Method::ManualMapRemoteThread)) {
    std::string e2;
    if (ExecViaRemoteThread(hProc, entry, base, cfg.timeoutMs, e2)) called = true;
    else if (method != InjectorConfig::Method::Auto) { r.error = "RemoteThread: " + e2; r.ntstatus = VACSAFE_E_EXEC_TIMEOUT; }
    else r.error = "Hijack: " + e + " | RemoteThread: " + e2;
  }
  if (!called && (method == InjectorConfig::Method::Auto || method == InjectorConfig::Method::ManualMapApc)) {
    std::string e3;
    if (ExecViaApc(hProc, entry, base, cfg.timeoutMs, e3)) called = true;
    else if (method != InjectorConfig::Method::Auto) { r.error = "APC: " + e3; r.ntstatus = VACSAFE_E_EXEC_TIMEOUT; }
    else r.error += " | APC: " + e3;
  }
  if (!called) {
    if (!r.ntstatus) r.ntstatus = VACSAFE_E_EXEC_TIMEOUT;
    VirtualFreeEx(hProc, base, 0, MEM_RELEASE);
    r.injectedBase = nullptr;
    CloseHandle(hProc);
    return r;
  }

  r.entryCalled = true;
  r.ntstatus = 0;
  if (cfg.eraseHeaders) r.stealthMask |= 0x1;
  if (cfg.unlinkLdr) r.stealthMask |= 0x2;
  if (cfg.spoofStartAddr) r.stealthMask |= 0x4;
  SecureZeroMemory(img.data(), img.size());
  CloseHandle(hProc);
  return r;
}

} // namespace vacsafe
