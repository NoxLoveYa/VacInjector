#pragma once
#include <cstdint>
#include <string>
#include <vector>
// Payload at-rest obfuscation, Phase 04 v1: XOR stream keyed by per-build BUILD_ID.
// Loader and pack_payload.py share the exact keystream (ASCII of BUILD_ID repeated).
// Goal is signature-break at rest (disk/network scanners see random bytes), not
// resistance against a live-memory analyst. ChaCha20 upgrade: Phase 08.
namespace vacsafe::crypto {
void XorInPlace(std::vector<uint8_t>& buf, const uint8_t* key, size_t keyLen);
// Decrypts buf in place using the compiled-in BUILD_ID. Returns false when no
// BUILD_ID is available (clean-tree build without running gen_build_id.py).
bool DecryptBuildId(std::vector<uint8_t>& buf, std::string& err);
}
