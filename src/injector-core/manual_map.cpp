#include "injector_core.h"
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <vector>

namespace vacsafe {

static DWORD ProtectFromCharacteristics(DWORD c) {
  bool exec = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
  bool read = (c & IMAGE_SCN_MEM_READ) != 0;
  bool write = (c & IMAGE_SCN_MEM_WRITE) != 0;
  if (exec && write) return PAGE_EXECUTE_READWRITE; // avoided post-fixup, kept only transiently
  if (exec && read) return PAGE_EXECUTE_READ;
  if (exec) return PAGE_EXECUTE;
  if (write && read) return PAGE_READWRITE;
  if (read) return PAGE_READONLY;
  if (write) return PAGE_READWRITE;
  return PAGE_NOACCESS;
}

static std::string WinErr(const char* what) {
  char buf[64];
  snprintf(buf, sizeof(buf), "%s (GLE=0x%08lX)", what, GetLastError());
  return buf;
}

void* ManualMap(HANDLE hProc, const uint8_t* image, size_t size, std::string& err) {
  if (!hProc || !image || size < sizeof(IMAGE_DOS_HEADER)) { err = "bad args"; return nullptr; }

  auto* dos = (IMAGE_DOS_HEADER*)image;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) { err = "not MZ"; return nullptr; }
  if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size) { err = "bad e_lfanew"; return nullptr; }

  auto* nth32 = (IMAGE_NT_HEADERS32*)(image + dos->e_lfanew);
  if (nth32->Signature != IMAGE_NT_SIGNATURE) { err = "not PE"; return nullptr; }

  bool is64 = (nth32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
  DWORD imageSize = 0;
  DWORD headerSize = 0;
  ULONGLONG prefBase = 0;
  IMAGE_DATA_DIRECTORY* dirs = nullptr;
  int numDirs = 0;
  IMAGE_SECTION_HEADER* sects = nullptr;
  int numSects = 0;

  if (is64) {
    auto* nt = (IMAGE_NT_HEADERS64*)nth32;
    imageSize = nt->OptionalHeader.SizeOfImage;
    headerSize = nt->OptionalHeader.SizeOfHeaders;
    prefBase = nt->OptionalHeader.ImageBase;
    dirs = nt->OptionalHeader.DataDirectory;
    numDirs = nt->OptionalHeader.NumberOfRvaAndSizes;
    sects = IMAGE_FIRST_SECTION(nt);
    numSects = nt->FileHeader.NumberOfSections;
  } else {
    auto* nt = (IMAGE_NT_HEADERS32*)nth32;
    imageSize = nt->OptionalHeader.SizeOfImage;
    headerSize = nt->OptionalHeader.SizeOfHeaders;
    prefBase = nt->OptionalHeader.ImageBase;
    dirs = nt->OptionalHeader.DataDirectory;
    numDirs = nt->OptionalHeader.NumberOfRvaAndSizes;
    sects = IMAGE_FIRST_SECTION(nt);
    numSects = nt->FileHeader.NumberOfSections;
  }
  if (!imageSize || imageSize > 256 * 1024 * 1024) { err = "bad SizeOfImage"; return nullptr; }

  // 1. Allocate RW in target (never RWX).
  void* remote = VirtualAllocEx(hProc, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { err = WinErr("VirtualAllocEx failed"); return nullptr; }

  auto cleanup = [&](const std::string& e) -> void* {
    err = e;
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    return nullptr;
  };

  // 2. Copy headers.
  SIZE_T written = 0;
  if (!WriteProcessMemory(hProc, remote, image, headerSize, &written) || written != headerSize)
    return cleanup(WinErr("header WPM failed"));

  // 3. Copy sections.
  for (int i = 0; i < numSects; ++i) {
    auto& s = sects[i];
    if (!s.SizeOfRawData || !s.PointerToRawData) continue;
    if ((size_t)s.PointerToRawData + s.SizeOfRawData > size)
      return cleanup("section raw out of range");
    void* dst = (uint8_t*)remote + s.VirtualAddress;
    SIZE_T w = 0;
    if (!WriteProcessMemory(hProc, dst, image + s.PointerToRawData, s.SizeOfRawData, &w) || w != s.SizeOfRawData)
      return cleanup(WinErr("section WPM failed"));
  }

  // 4. Relocs.
  ULONGLONG delta = (ULONGLONG)remote - prefBase;
  if (delta && numDirs > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
    auto& rel = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (rel.VirtualAddress && rel.Size) {
      // Read reloc block table: it was already copied to target, but easier to walk locally and patch target via RPM/WPM.
      DWORD off = 0;
      while (off < rel.Size) {
        if (rel.VirtualAddress + off + sizeof(IMAGE_BASE_RELOCATION) > imageSize) break;
        // Locate block in local image: RVA -> file offset via sections.
        // Read from local copy by mapping RVA through sections.
        auto rvaToLocal = [&](DWORD rva) -> uint8_t* {
          for (int i = 0; i < numSects; ++i) {
            DWORD va = sects[i].VirtualAddress, vsz = sects[i].Misc.VirtualSize ? sects[i].Misc.VirtualSize : sects[i].SizeOfRawData;
            if (rva >= va && rva < va + vsz) {
              DWORD d = rva - va;
              if (sects[i].PointerToRawData + d >= size) return nullptr;
              return (uint8_t*)image + sects[i].PointerToRawData + d;
            }
          }
          if (rva < headerSize) return (uint8_t*)image + rva;
          return nullptr;
        };
        uint8_t* blk = rvaToLocal(rel.VirtualAddress + off);
        if (!blk) break;
        auto* br = (IMAGE_BASE_RELOCATION*)blk;
        if (!br->SizeOfBlock) break;
        DWORD count = (br->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* items = (WORD*)(blk + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD k = 0; k < count; ++k) {
          WORD it = items[k];
          WORD type = it >> 12, ofs = it & 0x0FFF;
          DWORD patchRva = br->VirtualAddress + ofs;
          uintptr_t remoteAddr = (uintptr_t)remote + patchRva;
          if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
          if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
            SIZE_T rd = 0; ULONGLONG val = 0;
            SIZE_T want = (type == IMAGE_REL_BASED_DIR64) ? 8 : 4;
            if (!ReadProcessMemory(hProc, (LPCVOID)remoteAddr, &val, want, &rd) || rd != want)
              return cleanup(WinErr("reloc RPM failed"));
            val += delta;
            SIZE_T w = 0;
            if (!WriteProcessMemory(hProc, (LPVOID)remoteAddr, &val, want, &w) || w != want)
              return cleanup(WinErr("reloc WPM failed"));
          } else {
            // Unsupported (ARM etc.) — fail closed, don't silently skip.
            return cleanup("unsupported reloc type");
          }
        }
        if (!br->SizeOfBlock) break;
        off += br->SizeOfBlock;
      }
    }
  }

  // 5. Imports: resolve locally (system DLLs share base session-wide), write IAT remotely.
  if (numDirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
    auto& imp = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp.VirtualAddress && imp.Size) {
      auto rvaToLocal = [&](DWORD rva) -> uint8_t* {
        for (int i = 0; i < numSects; ++i) {
          DWORD va = sects[i].VirtualAddress, vsz = sects[i].Misc.VirtualSize ? sects[i].Misc.VirtualSize : sects[i].SizeOfRawData;
          if (rva >= va && rva < va + vsz) {
            DWORD d = rva - va;
            if ((size_t)sects[i].PointerToRawData + d >= size) return nullptr;
            return (uint8_t*)image + sects[i].PointerToRawData + d;
          }
        }
        if (rva < headerSize) return (uint8_t*)image + rva;
        return nullptr;
      };
      auto rvaToStr = [&](DWORD rva) -> const char* { return (const char*)rvaToLocal(rva); };
      for (DWORD d = 0;; ++d) {
        uint8_t* p = rvaToLocal(imp.VirtualAddress + d * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!p) return cleanup("import desc OOB");
        auto* id = (IMAGE_IMPORT_DESCRIPTOR*)p;
        if (!id->OriginalFirstThunk && !id->FirstThunk && !id->Name) break;
        const char* dll = rvaToStr(id->Name);
        if (!dll) return cleanup("import dll name OOB");
        HMODULE hDll = LoadLibraryA(dll);
        if (!hDll) return cleanup(std::string("LoadLibrary (loader) failed: ") + dll);
        DWORD oftRva = id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk;
        DWORD ftRva = id->FirstThunk;
        for (DWORD t = 0;; ++t) {
          uint8_t* oftP = rvaToLocal(oftRva + t * (is64 ? 8 : 4));
          if (!oftP) return cleanup("import thunk OOB");
          ULONGLONG raw = is64 ? *(ULONGLONG*)oftP : *(DWORD*)oftP;
          if (!raw) break;
          FARPROC fn = nullptr;
          bool byOrd = (is64 ? (raw & IMAGE_ORDINAL_FLAG64) : (raw & IMAGE_ORDINAL_FLAG32)) != 0;
          if (byOrd) {
            WORD ord = (WORD)(raw & 0xFFFF);
            fn = GetProcAddress(hDll, (LPCSTR)(uintptr_t)ord);
          } else {
            const char* fnName = rvaToStr((DWORD)raw + 2); // skip Hint
            if (!fnName) return cleanup("import-by-name OOB");
            fn = GetProcAddress(hDll, fnName);
          }
          if (!fn) return cleanup(std::string("GetProcAddress failed in ") + dll);
          uintptr_t iatAddr = (uintptr_t)remote + ftRva + t * (is64 ? 8 : 4);
          ULONGLONG v = (ULONGLONG)fn;
          SIZE_T w = 0;
          SIZE_T want = is64 ? 8 : 4;
          if (!WriteProcessMemory(hProc, (LPVOID)iatAddr, &v, want, &w) || w != want)
            return cleanup(WinErr("IAT WPM failed"));
        }
      }
    }
  }

  // 6. Final protects per section (RX for code, never RWX).
  for (int i = 0; i < numSects; ++i) {
    auto& s = sects[i];
    DWORD vsz = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
    if (!vsz) continue;
    DWORD prot = ProtectFromCharacteristics(s.Characteristics);
    if (prot == PAGE_EXECUTE_READWRITE) prot = PAGE_EXECUTE_READ; // harden: no RWX ever
    DWORD old = 0;
    void* dst = (uint8_t*)remote + s.VirtualAddress;
    VirtualProtectEx(hProc, dst, vsz, prot, &old);
  }
  // Headers -> RO.
  { DWORD old = 0; VirtualProtectEx(hProc, remote, headerSize, PAGE_READONLY, &old); }

  return remote;
}

} // namespace vacsafe
