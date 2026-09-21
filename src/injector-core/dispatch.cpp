#include "injector_core.h"
#include <windows.h>
#include <cstdio>
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

  void* entry = RemoteEntry(img.data(), base);
  if (!entry) { r.error = "no entry point (DLL needs DllMain)"; r.ntstatus = VACSAFE_E_IMPORT; VirtualFreeEx(hProc, base, 0, MEM_RELEASE); CloseHandle(hProc); return r; }

  bool called = false;
  auto method = cfg.method;
  if (method == InjectorConfig::Method::Auto || method == InjectorConfig::Method::ManualMapHijack) {
    if (ExecViaHijack(hProc, entry, base, cfg.timeoutMs, e)) called = true;
    else if (method != InjectorConfig::Method::Auto) { r.error = "Hijack: " + e; r.ntstatus = VACSAFE_E_EXEC_TIMEOUT; }
  }
  if (!called && (method == InjectorConfig::Method::Auto || method == InjectorConfig::Method::ManualMapApc)) {
    std::string e2;
    if (ExecViaApc(hProc, entry, base, cfg.timeoutMs, e2)) called = true;
    else if (method != InjectorConfig::Method::Auto) { r.error = "APC: " + e2; r.ntstatus = VACSAFE_E_EXEC_TIMEOUT; }
    else r.error = "Hijack: " + e + " | APC: " + e2;
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
