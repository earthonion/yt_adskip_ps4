#pragma once

#include <stddef.h>
#include <stdint.h>

struct HashRing {
  bool seen(uint64_t hash);

private:
  static constexpr size_t kCapacity = 64;
  uint64_t values_[kCapacity] = {};
  size_t next_ = 0;
};

uint64_t fnv1a64(const void* data, size_t len);

bool looks_printable_text(const uint8_t* data, size_t len, double min_ratio = 0.85);
const char* infer_ext(const uint8_t* data, size_t len);
bool looks_interesting(const uint8_t* data, size_t len);

size_t find_substring(const char* haystack, size_t hay_len, const char* needle);
size_t find_last_substring(const char* haystack, size_t hay_len, const char* needle);

