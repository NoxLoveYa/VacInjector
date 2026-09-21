#pragma once
#include <cstddef>
#include <cstdint>
// Compile-time XOR string encryption (Phase 04).
// Ciphertext lives in .rdata; plaintext exists only in transient stack buffers.
// Raw-path safe: no CRT, no heap, force-inlined byte loops.
//
// LIFETIME RULE: VACSAFE_OBF(s) yields a pointer valid ONLY to the end of the
// enclosing full expression. Use it as an immediate call argument and NEVER store it:
//   OutputDebugStringA(VACSAFE_OBF("hi"));   // OK
//   const char* p = VACSAFE_OBF("hi"); ...   // DANGLING - NEVER
// For a persistent local copy use VACSAFE_OBF_BUF(name, "literal").
// Argument must be a string LITERAL (sizeof trick), avoid commas inside.
namespace vacsafe::obf {

template <size_t N>
struct Enc {
  char data[N];
  constexpr Enc(const char (&s)[N], uint8_t k) : data{} {
    for (size_t i = 0; i < N; ++i) data[i] = (char)(s[i] ^ (uint8_t)(k + i * 0x25));
  }
};

template <size_t N>
struct Dec {
  char buf[N];
  Dec(const Enc<N>& e, uint8_t k) {
    for (size_t i = 0; i < N; ++i) buf[i] = (char)(e.data[i] ^ (uint8_t)(k + i * 0x25));
  }
  const char* c_str() { return buf; }
};

} // namespace vacsafe::obf

#define VACSAFE_OBF_KEYFOR(s) ((uint8_t)(0x5A ^ sizeof(s)))
#define VACSAFE_OBF(s) \
  (vacsafe::obf::Dec<sizeof(s)>(vacsafe::obf::Enc<sizeof(s)>(s, VACSAFE_OBF_KEYFOR(s)), VACSAFE_OBF_KEYFOR(s)).c_str())
#define VACSAFE_OBF_BUF(name, s)                                                                               \
  char name[sizeof(s)];                                                                                        \
  {                                                                                                            \
    constexpr vacsafe::obf::Enc<sizeof(s)> name##_enc(s, VACSAFE_OBF_KEYFOR(s));                                \
    for (size_t name##_i = 0; name##_i < sizeof(s); ++name##_i)                                                 \
      name[name##_i] = (char)(name##_enc.data[name##_i] ^ (uint8_t)(VACSAFE_OBF_KEYFOR(s) + name##_i * 0x25));   \
  }
