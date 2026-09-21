#include "common.h"
#include "nt_api.h"
#include "crypto.h"
#if __has_include("build_id.h")
#include "build_id.h"
#endif
namespace vacsafe {
// NOTE: nt::HashName/GetProcByHash live in nt_api.cpp (CRT-free TU).
namespace crypto {
void XorInPlace(std::vector<uint8_t>& buf, const uint8_t* key, size_t keyLen) {
  if (!keyLen) return;
  for (size_t i = 0; i < buf.size(); ++i) buf[i] ^= key[i % keyLen];
}
bool DecryptBuildId(std::vector<uint8_t>& buf, std::string& err) {
#ifdef VACSAFE_BUILD_ID
  const char* bid = VACSAFE_BUILD_ID;
  size_t n = 0;
  while (bid[n]) ++n; // no CRT strlen: keep this TU raw-path friendly
  if (!n) { err = "empty BUILD_ID (run tools/gen_build_id.py)"; return false; }
  XorInPlace(buf, (const uint8_t*)bid, n);
  return true;
#else
  (void)buf;
  err = "no BUILD_ID compiled in (run tools/gen_build_id.py, then rebuild)";
  return false;
#endif
}
} // namespace crypto
} // namespace vacsafe
