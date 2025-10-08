#include "util.h"

#include <string.h>

uint64_t fnv1a64(const void* data, size_t len) {
  const uint8_t* bytes = static_cast<const uint8_t*>(data);
  uint64_t h = 1469598103934665603ull;
  for (size_t i = 0; i < len; ++i) {
    h ^= bytes[i];
    h *= 1099511628211ull;
  }
  return h;
}

bool looks_printable_text(const uint8_t* data, size_t len, double min_ratio) {
  if (!data || len == 0) return false;
  size_t printable = 0;
  for (size_t i = 0; i < len; ++i) {
    uint8_t c = data[i];
    if ((c >= 0x20 && c < 0x7F) || c == '\t' || c == '\r' || c == '\n') {
      ++printable;
    }
  }
  return static_cast<double>(printable) / static_cast<double>(len) >= min_ratio;
}

static bool starts_with(const uint8_t* data, size_t len, const char* prefix) {
  size_t plen = prefix ? strlen(prefix) : 0;
  return prefix && len >= plen && memcmp(data, prefix, plen) == 0;
}

const char* infer_ext(const uint8_t* data, size_t len) {
  if (!data || len == 0) return ".bin";
  if (len >= 1 && (data[0] == '{' || data[0] == '[')) return ".json";
  if (len >= 2 && data[0] == '/' && data[1] == '*') return ".js";
  if (looks_printable_text(data, len, 0.92)) {
    static const char* kJsMarkers[] = {
        "function", "var ", "let ", "const ", "=>", "window.",
        "self.", "this."};
    for (const char* marker : kJsMarkers) {
      const char* end = reinterpret_cast<const char*>(data) + len;
      const char* p = reinterpret_cast<const char*>(data);
      size_t marker_len = strlen(marker);
      while (p && p + marker_len <= end) {
        const char* found = static_cast<const char*>(memchr(p, marker[0], end - p));
        if (!found) break;
        if (static_cast<size_t>(end - found) >= marker_len &&
            memcmp(found, marker, marker_len) == 0) {
          return ".js";
        }
        p = found + 1;
      }
    }
    return ".txt";
  }
  return ".bin";
}

static bool denylist_hit(const uint8_t* data, size_t len) {
  static const char* kDeny[] = {
      "mark_", "play", "pause", "stop", "seekto", "seekbackward",
      "seekforward", "previoustrack", "nexttrack", "skipad",
      "handleEvent", "mark_tvcs", "mark_tvce", "mark_nps",
      "mark_srt", "mark_nreqs", "mark_nress", "mark_nrese",
      "mark_main_js_r", "mark_base_js_r", "mark_veb_s", "mark_br_s",
      "mark_ld_s"};
  for (const char* prefix : kDeny) {
    if (starts_with(data, len, prefix)) return true;
  }
  return false;
}

bool looks_interesting(const uint8_t* data, size_t len) {
  if (!data || len == 0) return false;
  if (len >= 4096) return true;
  if (denylist_hit(data, len)) return false;
  if (len < 16) return false;
  if (data[0] == '{' || data[0] == '[') return true;
  if (starts_with(data, len, "this.") || starts_with(data, len, "var ") ||
      starts_with(data, len, "let ") || starts_with(data, len, "const ") ||
      starts_with(data, len, "(function") ||
      starts_with(data, len, "!function") ||
      starts_with(data, len, "function ")) {
    return true;
  }
  if (starts_with(data, len, "http://") || starts_with(data, len, "https://")) {
    return true;
  }
  return looks_printable_text(data, len, 0.9) && len >= 128;
}

size_t find_substring(const char* haystack, size_t hay_len, const char* needle) {
  if (!haystack || !needle) return SIZE_MAX;
  size_t needle_len = strlen(needle);
  if (needle_len == 0 || hay_len < needle_len) return SIZE_MAX;
  for (size_t i = 0; i + needle_len <= hay_len; ++i) {
    if (memcmp(haystack + i, needle, needle_len) == 0) {
      return i;
    }
  }
  return SIZE_MAX;
}

size_t find_last_substring(const char* haystack, size_t hay_len, const char* needle) {
  if (!haystack || !needle) return SIZE_MAX;
  size_t needle_len = strlen(needle);
  if (needle_len == 0 || hay_len < needle_len) return SIZE_MAX;
  size_t last = SIZE_MAX;
  for (size_t i = 0; i + needle_len <= hay_len; ++i) {
    if (memcmp(haystack + i, needle, needle_len) == 0) {
      last = i;
    }
  }
  return last;
}

bool HashRing::seen(uint64_t hash) {
  for (size_t i = 0; i < kCapacity; ++i) {
    if (values_[i] == hash) {
      return true;
    }
  }
  values_[next_] = hash;
  next_ = (next_ + 1) % kCapacity;
  return false;
}

