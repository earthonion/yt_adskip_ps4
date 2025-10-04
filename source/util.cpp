#include "util.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "patch.h"
#include "utils.h"

extern "C" void mh_log(const char* fmt, ...);

#define MH_LOG(fmt, ...) mh_log("[minihook] " fmt "\n", ##__VA_ARGS__)

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

namespace {

bool starts_with(const uint8_t* data, size_t len, const char* prefix) {
  if (!data || !prefix) {
    return false;
  }
  size_t plen = std::strlen(prefix);
  return len >= plen && std::memcmp(data, prefix, plen) == 0;
}

bool denylist_hit(const uint8_t* data, size_t len) {
  static const char* kDeny[] = {
      "mark_", "play", "pause", "stop", "seekto", "seekbackward",
      "seekforward", "previoustrack", "nexttrack", "skipad",
      "handleEvent", "mark_tvcs", "mark_tvce", "mark_nps",
      "mark_srt", "mark_nreqs", "mark_nress", "mark_nrese",
      "mark_main_js_r", "mark_base_js_r", "mark_veb_s", "mark_br_s",
      "mark_ld_s"};
  for (const char* prefix : kDeny) {
    if (starts_with(data, len, prefix)) {
      return true;
    }
  }
  return false;
}

std::vector<uint8_t> read_remote_buffer(uint64_t addr, size_t length) {
  std::vector<uint8_t> out(length, 0);
  if (!addr || length == 0 || !is_canonical_address(addr)) {
    return out;
  }
  sys_proc_ro(addr, out.data(), out.size());
  return out;
}

bool read_remote_ascii(uint64_t addr, size_t max_bytes, std::string& out) {
  if (!addr || !is_canonical_address(addr) || max_bytes == 0) {
    return false;
  }
  size_t fetch = std::min<size_t>(max_bytes, 2048);
  std::vector<char> buffer(fetch + 1, 0);
  sys_proc_ro(addr, buffer.data(), fetch);
  buffer[fetch] = '\0';

  size_t actual = strnlen(buffer.data(), fetch);
  if (!looks_printable_text(reinterpret_cast<const uint8_t*>(buffer.data()), actual, 0.55)) {
    return false;
  }
  out.assign(buffer.data(), actual);
  return true;
}

bool remote_buffer_looks_utf16le(uint64_t remote_addr) {
  if (!remote_addr || !is_canonical_address(remote_addr)) {
    return false;
  }
  std::array<uint8_t, 64> probe{};
  sys_proc_ro(remote_addr, probe.data(), probe.size());
  size_t zero_high = 0;
  for (size_t i = 1; i < probe.size(); i += 2) {
    if (probe[i] == 0) {
      ++zero_high;
    }
  }
  return zero_high >= (probe.size() / 4);
}

void utf8_to_utf16le(const std::string& src, std::vector<uint8_t>& out) {
  out.clear();
  out.reserve(src.size() * 2 + 2);
  const unsigned char* p = reinterpret_cast<const unsigned char*>(src.data());
  size_t i = 0;
  while (i < src.size()) {
    uint32_t cp = 0;
    unsigned char c = p[i];
    if (c < 0x80) {
      cp = c;
      i += 1;
    } else if ((c >> 5) == 0x6 && (i + 1) < src.size()) {
      cp = ((p[i] & 0x1F) << 6) | (p[i + 1] & 0x3F);
      i += 2;
    } else if ((c >> 4) == 0xE && (i + 2) < src.size()) {
      cp = ((p[i] & 0x0F) << 12) | ((p[i + 1] & 0x3F) << 6) |
           (p[i + 2] & 0x3F);
      i += 3;
    } else if ((c >> 3) == 0x1E && (i + 3) < src.size()) {
      cp = ((p[i] & 0x07) << 18) | ((p[i + 1] & 0x3F) << 12) |
           ((p[i + 2] & 0x3F) << 6) | (p[i + 3] & 0x3F);
      i += 4;
    } else {
      cp = 0xFFFD;
      i += 1;
    }

    if (cp <= 0xFFFF) {
      uint16_t w = static_cast<uint16_t>(cp);
      out.push_back(static_cast<uint8_t>(w & 0xFF));
      out.push_back(static_cast<uint8_t>((w >> 8) & 0xFF));
    } else {
      cp -= 0x10000;
      uint16_t hi = static_cast<uint16_t>((cp >> 10) + 0xD800);
      uint16_t lo = static_cast<uint16_t>((cp & 0x3FF) + 0xDC00);
      out.push_back(static_cast<uint8_t>(hi & 0xFF));
      out.push_back(static_cast<uint8_t>((hi >> 8) & 0xFF));
      out.push_back(static_cast<uint8_t>(lo & 0xFF));
      out.push_back(static_cast<uint8_t>((lo >> 8) & 0xFF));
    }
  }
}

void log_remote_ascii_preview(uint64_t remote_addr, size_t limit) {
  if (!is_canonical_address(remote_addr) || !limit) {
    return;
  }
  size_t take = std::min(limit, static_cast<size_t>(128));
  std::vector<uint8_t> buf(take, 0);
  sys_proc_ro(remote_addr, buf.data(), take);
  std::string ascii;
  ascii.reserve(take);
  for (size_t i = 0; i < take; ++i) {
    unsigned char c = buf[i];
    ascii.push_back((c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.');
  }
  MH_LOG("[inject.verify] remote@%p preview[%zu] \"%s\"",
         (void*)remote_addr, take, ascii.c_str());
}

struct ScriptCacheEntry {
  void* owner = nullptr;
  std::string script;
  uint64_t hash = 0;
};

std::vector<ScriptCacheEntry> g_script_cache;
HashRing g_seen_hashes;
std::vector<void*> g_injected_contexts;
bool g_injected_null_context = false;

std::string g_js_payload;
bool g_js_payload_loaded = false;
bool g_js_payload_failed = false;

}  // namespace

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

const char* infer_ext(const uint8_t* data, size_t len) {
  if (!data || len == 0) return ".bin";
  if (len >= 1 && (data[0] == '{' || data[0] == '[')) return ".json";
  if (len >= 2 && data[0] == '/' && data[1] == '*') return ".js";
  if (looks_printable_text(data, len, 0.92)) {
    static const char* kJsMarkers[] = {
        "function", "var ", "let ", "const ", "=>", "window.",
        "self.", "this."};
    for (const char* marker : kJsMarkers) {
      if (find_substring(reinterpret_cast<const char*>(data), len, marker) != SIZE_MAX) {
        return ".js";
      }
    }
    return ".txt";
  }
  return ".bin";
}

size_t find_substring(const char* haystack, size_t hay_len, const char* needle) {
  if (!haystack || !needle) return SIZE_MAX;
  size_t needle_len = std::strlen(needle);
  if (needle_len == 0 || hay_len < needle_len) return SIZE_MAX;
  for (size_t i = 0; i + needle_len <= hay_len; ++i) {
    if (std::memcmp(haystack + i, needle, needle_len) == 0) {
      return i;
    }
  }
  return SIZE_MAX;
}

size_t find_last_substring(const char* haystack, size_t hay_len, const char* needle) {
  if (!haystack || !needle) return SIZE_MAX;
  size_t needle_len = std::strlen(needle);
  if (needle_len == 0 || hay_len < needle_len) return SIZE_MAX;
  size_t last = SIZE_MAX;
  for (size_t i = 0; i + needle_len <= hay_len; ++i) {
    if (std::memcmp(haystack + i, needle, needle_len) == 0) {
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

bool is_canonical_address(uint64_t addr) {
  return (addr & 0xFFFF800000000000ull) == 0;
}

void log_memory_hexdump(const void* addr, size_t bytes) {
  if (!addr || bytes == 0) {
    return;
  }

  uintptr_t raw = reinterpret_cast<uintptr_t>(addr);
  if (!is_canonical_address(raw)) {
    //MH_LOG("[prepare] hexdump skipped (non-canonical %p)", addr);
    return;
  }

  std::vector<uint8_t> buffer(bytes, 0);
  sys_proc_ro(static_cast<uint64_t>(raw), buffer.data(), buffer.size());

  constexpr size_t kRow = 16;
  char hex[kRow * 3 + 1];
  char ascii[kRow + 1];

  for (size_t offset = 0; offset < buffer.size(); offset += kRow) {
    size_t row_len = std::min(kRow, buffer.size() - offset);
    for (size_t i = 0; i < row_len; ++i) {
      uint8_t byte = buffer[offset + i];
      std::snprintf(&hex[i * 3], sizeof(hex) - i * 3, "%02x ", byte);
      ascii[i] = std::isprint(byte) ? static_cast<char>(byte) : '.';
    }
    hex[row_len * 3] = '\0';
    ascii[row_len] = '\0';
    //MH_LOG("[prepare] mem[%p+0x%02zx] %s|%s|", addr, offset, hex, ascii);
  }
}

void log_preview_bounded(const uint8_t* b, size_t n, size_t max_chars) {
  size_t take = n < max_chars ? n : max_chars;
  char buf[256 + 1];
  if (take > 256) take = 256;
  for (size_t i = 0; i < take; ++i) {
    uint8_t c = b[i];
    buf[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
  }
  buf[take] = 0;
  MH_LOG("[execute.preview 0..%zu] %s", take, buf);
}

bool buffer_has_anchor(const char* data, size_t len) {
  if (!data || !len) {
    return false;
  }
  constexpr const char strict1[] = "'use strict';";
  constexpr const char strict2[] = "\"use strict\"";
  return find_substring(data, len, strict1) != SIZE_MAX ||
         find_substring(data, len, strict2) != SIZE_MAX;
}

bool ensure_js_payload_loaded() {
  if (g_js_payload_loaded) {
    return true;
  }

  static const char kHardcodedJs[] =
      "(function(){\n"
      "  if (window.__MH_ADSKIP_READY) { return; }\n"
      "  window.__MH_ADSKIP_READY = true;\n"
      "  \n"
      "  var bannerShown = false;\n"
      "  var adSkipActive = false;\n"
      "  \n"
      "  function showBanner() {\n"
      "    if (bannerShown) return;\n"
      "    try {\n"
      "      if (!document.documentElement) return;\n"
      "      var bannerId = '__MH_ADSKIP_BANNER';\n"
      "      if (!document.getElementById(bannerId)) {\n"
      "        var banner = document.createElement('div');\n"
      "        banner.id = bannerId;\n"
      "        banner.textContent = 'Ad skip enabled';\n"
      "        banner.style.position = 'fixed';\n"
      "        banner.style.left = '10px';\n"
      "        banner.style.bottom = '10px';\n"
      "        banner.style.zIndex = '2147483647';\n"
      "        banner.style.background = 'rgba(0,0,0,0.8)';\n"
      "        banner.style.color = '#00FF99';\n"
      "        banner.style.padding = '8px 14px';\n"
      "        banner.style.font = '16px/1.2 sans-serif';\n"
      "        banner.style.borderRadius = '4px';\n"
      "        banner.style.boxShadow = '0 3px 10px rgba(0,0,0,0.4)';\n"
      "        document.documentElement.appendChild(banner);\n"
      "        bannerShown = true;\n"
      "        setTimeout(function(){ try { var b = document.getElementById(bannerId); if (b) b.remove(); } catch(_) {} }, 4000);\n"
      "      }\n"
      "    } catch (_) {}\n"
      "  }\n"
      "  \n"
      "  function skipAds() {\n"
      "    try {\n"
      "      var videos = document.getElementsByClassName('html5-main-video');\n"
      "      if (document.getElementsByClassName('ad-showing').length > 0 && videos.length > 0) {\n"
      "        var vid = videos[0];\n"
      "        if (vid && typeof vid.duration === 'number' && isFinite(vid.duration) && vid.duration > 0) {\n"
      "          vid.currentTime = vid.duration;\n"
      "        }\n"
      "      }\n"
      "    } catch (_) {}\n"
      "  }\n"
      "  \n"
      "  function init() {\n"
      "    showBanner();\n"
      "    if (!adSkipActive) {\n"
      "      adSkipActive = true;\n"
      "      setInterval(skipAds, 50);\n"
      "    }\n"
      "  }\n"
      "  \n"
      "  if (document.readyState === 'loading') {\n"
      "    document.addEventListener('DOMContentLoaded', init);\n"
      "  } else {\n"
      "    init();\n"
      "  }\n"
      "})();\n";

  g_js_payload.assign(kHardcodedJs, kHardcodedJs + sizeof(kHardcodedJs) - 1);
  g_js_payload_loaded = true;
  g_js_payload_failed = false;
  MH_LOG("[execute.inject] loaded hardcoded payload %zu bytes", g_js_payload.size());
  return true;
}

const std::string& get_js_payload() {
  return g_js_payload;
}

void reset_js_payload_state() {
  g_js_payload.clear();
  g_js_payload_loaded = false;
  g_js_payload_failed = false;
}

bool write_payload_to_remote(uint64_t remote_data_ptr,
                             uint64_t header_addr,
                             const StringLikeLayout& layout,
                             const std::string& payload,
                             uint64_t remote_cap,
                             uint64_t original_size) {
  if (!is_canonical_address(remote_data_ptr)) {
    MH_LOG("[inject.verify] remote data ptr invalid %p", (void*)remote_data_ptr);
    return false;
  }
  if (!remote_cap || remote_cap > (1ull << 36)) {
    MH_LOG("[inject.verify] remote cap out of range %llu",
           static_cast<unsigned long long>(remote_cap));
    return false;
  }

  bool use_utf16 = remote_buffer_looks_utf16le(remote_data_ptr);
  size_t cap_bytes = static_cast<size_t>(std::min<uint64_t>(remote_cap, SIZE_MAX));

  if (!use_utf16) {
    size_t payload_len = payload.size();
    if (payload_len > cap_bytes) {
      MH_LOG("[inject.verify] utf8 payload %zu > cap %zu", payload_len, cap_bytes);
      return false;
    }
    sys_proc_rw(remote_data_ptr,
                const_cast<char*>(payload.data()),
                payload_len);
    uint64_t new_size = static_cast<uint64_t>(payload_len);
    sys_proc_rw(header_addr + layout.size_off,
                &new_size,
                sizeof(new_size));

    size_t verify_len = std::min(payload_len, static_cast<size_t>(256));
    if (verify_len) {
      std::vector<uint8_t> verify(verify_len, 0);
      sys_proc_ro(remote_data_ptr, verify.data(), verify.size());
      bool matches = std::memcmp(payload.data(), verify.data(), verify_len) == 0;
      MH_LOG("[inject.verify] utf8 roundtrip=%d bytes=%zu", matches ? 1 : 0,
             verify_len);
    }
    log_remote_ascii_preview(remote_data_ptr, std::min(payload_len, static_cast<size_t>(96)));
    MH_LOG("[inject.remote] encoding=utf8 size=%zu cap=%zu", payload_len, cap_bytes);
    return true;
  }

  std::vector<uint8_t> utf16;
  utf8_to_utf16le(payload, utf16);
  size_t payload_bytes = utf16.size();
  if (payload_bytes > cap_bytes) {
    MH_LOG("[inject.verify] utf16 payload %zu > cap %zu", payload_bytes, cap_bytes);
    return false;
  }
  sys_proc_rw(remote_data_ptr, utf16.data(), payload_bytes);

  uint64_t code_units = static_cast<uint64_t>(utf16.size() / 2);
  uint64_t new_size = code_units;
  if (original_size && original_size == remote_cap) {
    new_size = static_cast<uint64_t>(payload_bytes);
  }
  sys_proc_rw(header_addr + layout.size_off, &new_size, sizeof(new_size));

  size_t verify_len = std::min(payload_bytes, static_cast<size_t>(256));
  if (verify_len) {
    std::vector<uint8_t> verify(verify_len, 0);
    sys_proc_ro(remote_data_ptr, verify.data(), verify.size());
    bool matches = std::memcmp(utf16.data(), verify.data(), verify_len) == 0;
    MH_LOG("[inject.verify] utf16 roundtrip=%d bytes=%zu", matches ? 1 : 0,
           verify_len);
  }
  log_remote_ascii_preview(remote_data_ptr, std::min(payload_bytes, static_cast<size_t>(96)));
  MH_LOG("[inject.remote] encoding=utf16 size=%zu cap=%zu code_units=%llu",
         payload_bytes, cap_bytes,
         static_cast<unsigned long long>(code_units));
  return true;
}

bool cache_script_source(void* self, const std::string& script,
                         uint64_t* out_hash) {
  if (!self) {
    return false;
  }
  uint64_t hash = djb2_hash(script.c_str());
  if (out_hash) {
    *out_hash = hash;
  }
  bool seen = g_seen_hashes.seen(hash);
  for (auto& entry : g_script_cache) {
    if (entry.owner == self) {
      entry.script = script;
      entry.hash = hash;
      return !seen;
    }
  }
  if (g_script_cache.size() >= 64) {
    g_script_cache.erase(g_script_cache.begin());
  }
  g_script_cache.push_back({self, script, hash});
  return !seen;
}

bool lookup_script_source(void* self, std::string& out) {
  for (auto it = g_script_cache.rbegin(); it != g_script_cache.rend(); ++it) {
    if (it->owner == self) {
      out = it->script;
      return true;
    }
  }
  return false;
}

void clear_script_cache() {
  g_script_cache.clear();
  g_seen_hashes = HashRing{};
}

bool context_already_injected(void* context) {
  if (!context) {
    return g_injected_null_context;
  }
  return std::find(g_injected_contexts.begin(), g_injected_contexts.end(), context) !=
         g_injected_contexts.end();
}

void remember_context(void* context) {
  if (!context) {
    g_injected_null_context = true;
    return;
  }
  if (std::find(g_injected_contexts.begin(), g_injected_contexts.end(), context) !=
      g_injected_contexts.end()) {
    return;
  }
  constexpr size_t kMaxTrackedContexts = 64;
  if (g_injected_contexts.size() >= kMaxTrackedContexts) {
    g_injected_contexts.erase(g_injected_contexts.begin());
  }
  g_injected_contexts.push_back(context);
}

void clear_context_tracking() {
  g_injected_contexts.clear();
  g_injected_null_context = false;
}

bool try_extract_script_from_candidate(uint64_t candidate, std::string& out,
                                       StringLikeLayout* out_layout) {
  out.clear();
  if (out_layout) {
    out_layout->valid = false;
  }
  if (!candidate || !is_canonical_address(candidate)) {
    return false;
  }

  constexpr size_t kProbe = 0x100;
  std::array<uint8_t, kProbe> header{};
  sys_proc_ro(candidate, header.data(), header.size());

  auto read_u64 = [&](size_t offset) -> uint64_t {
    if (offset + sizeof(uint64_t) > header.size()) {
      return 0;
    }
    uint64_t value = 0;
    std::memcpy(&value, header.data() + offset, sizeof(value));
    return value;
  };

  auto try_pointer_and_length = [&](size_t d_off, size_t n_off, size_t c_off) -> bool {
    uint64_t data_ptr = read_u64(d_off);
    uint64_t len      = read_u64(n_off);
    uint64_t cap      = read_u64(c_off);
    if (!data_ptr || !is_canonical_address(data_ptr)) {
      return false;
    }
    if (len == 0 || len > (1ULL << 20)) {
      return false;
    }
    if (cap < len || cap > (1ULL << 20)) {
      return false;
    }
    std::vector<uint8_t> temp = read_remote_buffer(data_ptr, static_cast<size_t>(len));
    if (temp.empty()) {
      return false;
    }
    size_t sample = std::min<size_t>(temp.size(), 512);
    if (!looks_printable_text(temp.data(), sample, 0.55)) {
      return false;
    }
    out.assign(reinterpret_cast<const char*>(temp.data()), temp.size());
    if (out_layout) {
      out_layout->valid = true;
      out_layout->data_off = d_off;
      out_layout->size_off = n_off;
      out_layout->cap_off  = c_off;
      out_layout->header_span = std::max<size_t>(0x40, std::max({d_off, n_off, c_off}) + 8);
      MH_LOG("[extract.layout] found at data@0x%zx size@0x%zx cap@0x%zx ptr=%p len=%llu cap=%llu",
             d_off, n_off, c_off, (void*)data_ptr,
             static_cast<unsigned long long>(len), static_cast<unsigned long long>(cap));
    }
    return true;
  };

  for (size_t base = 0; base + 24 <= 0x80; base += 8) {
    if (try_pointer_and_length(base, base + 8, base + 16)) {
      return true;
    }
  }

  const size_t offsets[] = {0x18, 0x20, 0x28, 0x30, 0x38,
                            0x40, 0x48, 0x50, 0x58, 0x60,
                            0x68, 0x70, 0x78, 0x80, 0x88,
                            0x90, 0x98, 0xa0, 0xa8, 0xb0,
                            0xb8, 0xc0, 0xc8, 0xd0, 0xd8,
                            0xe0, 0xe8, 0xf0};
  for (size_t off : offsets) {
    if (try_pointer_and_length(off, off + 8, off + 16)) {
      return true;
    }
  }

  constexpr size_t inline_cap = sizeof(std::string);
  if (inline_cap <= header.size()) {
    uint8_t inline_len = header[inline_cap - 1];
    if (inline_len > 0 && inline_len < inline_cap && inline_len < header.size()) {
      if (looks_printable_text(header.data(), inline_len, 0.55)) {
        out.assign(reinterpret_cast<const char*>(header.data()), inline_len);
        return true;
      }
    }
  }

  for (size_t off = 0; off + sizeof(uint64_t) <= header.size(); off += sizeof(uint64_t)) {
    uint64_t maybe_ptr = read_u64(off);
    if (read_remote_ascii(maybe_ptr, 2048, out)) {
      MH_LOG("[extract.fallback] found string via pointer at offset 0x%zx -> %p len=%zu",
             off, (void*)maybe_ptr, out.size());
      if (out_layout && !out.empty()) {
        // Assume this is a pointer at offset, try to infer the layout
        // Check if there's size/cap following the pointer
        if (off + 24 <= header.size()) {
          uint64_t maybe_size = read_u64(off + 8);
          uint64_t maybe_cap = read_u64(off + 16);
          MH_LOG("[extract.fallback] checking layout: size=%llu cap=%llu (string_len=%zu)",
                 static_cast<unsigned long long>(maybe_size),
                 static_cast<unsigned long long>(maybe_cap),
                 out.size());

          // Accept if cap is reasonable, even if size is 0
          // We'll use the actual string length we extracted
          if (maybe_cap > 0 && maybe_cap <= (1ULL << 20) &&
              (maybe_size == 0 || (maybe_size <= (1ULL << 20) && maybe_cap >= maybe_size))) {
            out_layout->valid = true;
            out_layout->data_off = off;
            out_layout->size_off = off + 8;
            out_layout->cap_off = off + 16;
            out_layout->header_span = std::max<size_t>(0x40, off + 24);
            MH_LOG("[extract.fallback] layout validated! data@0x%zx size@0x%zx cap@0x%zx (size_was_zero=%d)",
                   off, off + 8, off + 16, maybe_size == 0 ? 1 : 0);
          } else {
            MH_LOG("[extract.fallback] layout validation failed");
          }
        }
      }
      return true;
    }
  }

  return false;
}

void patch_unsafe_inline_assignment() {
  OrbisKernelModuleInfo info{};
  uint64_t base = 0;
  uint32_t size = 0;
  if (!get_module_info(info, "eboot.bin", &base, &size)) {
    MH_LOG("[patch] failed to resolve eboot.bin info");
    return;
  }

  u8* hit = PatternScan(base, size, "C6 47 52 01 B0 01");
  if (!hit) {
    MH_LOG("[patch] unsafe-inline pattern not found");
    return;
  }

  uint8_t nops[4] = {0x90, 0x90, 0x90, 0x90};
  sys_proc_rw((uint64_t)hit, nops, sizeof(nops));
  MH_LOG("[patch] unsafe-inline mov patched @%p", (void*)hit);
}
