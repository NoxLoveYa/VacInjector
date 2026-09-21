#pragma once
#include "common.h"
// NT API wrappers (hash-resolved at runtime, no IAT strings for sensitive APIs).
// Phase 03 task: implement via PEB walk + djb2/fnv1a hash in nt_api.cpp.
namespace vacsafe::nt {
void* GetProcByHash(const wchar_t* module, uint32_t hash);
uint32_t HashName(const char* s);
} // namespace vacsafe::nt
