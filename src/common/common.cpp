#include "common.h"
#include "nt_api.h"
#include "crypto.h"
namespace vacsafe {
namespace nt {
uint32_t HashName(const char* s) {
  uint32_t h = 5381;
  while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
  return h;
}
void* GetProcByHash(const wchar_t*, uint32_t) { return nullptr; } // TODO Phase 03
} // namespace nt
namespace crypto {
void XorInPlace(std::vector<uint8_t>& buf, const uint8_t* key, size_t keyLen) {
  for (size_t i = 0; i < buf.size(); ++i) buf[i] ^= key[i % keyLen];
}
} // namespace crypto
} // namespace vacsafe
