#pragma once
#include <cstdint>
#include <vector>
// Payload at-rest crypto: ChaCha20 + per-build key (tools/pack_payload.py counterpart).
// Phase 04 task: implement DecryptInPlace here, key passed via loader RAM only.
namespace vacsafe::crypto {
void XorInPlace(std::vector<uint8_t>& buf, const uint8_t* key, size_t keyLen);
}
