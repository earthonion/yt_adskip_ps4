#include "util.h"
#include "patch.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <string>
#include <vector>

extern "C" void mh_log(const char* fmt, ...);

#define MH_LOG(fmt, ...) mh_log("[minihook] " fmt "\n", ##__VA_ARGS__)

namespace {

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

std::string g_js_payload;
bool g_js_payload_loaded = false;

}  // namespace

bool is_canonical_address(uint64_t addr) {
  return (addr & 0xFFFF800000000000ull) == 0;
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

bool ensure_js_payload_loaded() {
  if (g_js_payload_loaded) {
    return true;
  }

  static const char kHardcodedJs[] =
      "(function(){\n"
      "  if (window.__MH_SPONSORBLOCK_LOADED) { return; }\n"
      "  window.__MH_SPONSORBLOCK_LOADED = true;\n"
      "  \n"
      "  var sponsorSegments = [];\n"
      "  var currentVideoId = null;\n"
      "  var segmentsSkipped = 0;\n"
      "  \n"
      "  function showToast(title, subtitle) {\n"
      "    try {\n"
      "      var popupAction = {\n"
      "        openPopupAction: {\n"
      "          popupType: 'TOAST',\n"
      "          popup: {\n"
      "            overlayToastRenderer: {\n"
      "              title: { simpleText: title },\n"
      "              subtitle: { simpleText: subtitle }\n"
      "            }\n"
      "          }\n"
      "        }\n"
      "      };\n"
      "      for (var key in window._yttv) {\n"
      "        if (window._yttv[key] && window._yttv[key].instance && window._yttv[key].instance.resolveCommand) {\n"
      "          window._yttv[key].instance.resolveCommand(popupAction);\n"
      "          break;\n"
      "        }\n"
      "      }\n"
      "    } catch(e) {}\n"
      "  }\n"
      "  \n"
      "  setTimeout(function() {\n"
      "    showToast('SponsorBlock Enabled', 'Sponsored segments will be automatically skipped');\n"
      "  }, 2000);\n"
      "  \n"
      "  function getVideoId() {\n"
      "    try {\n"
      "      var match = window.location.hash.match(/[?&]v=([^&]+)/);\n"
      "      return match ? match[1] : null;\n"
      "    } catch(e) {\n"
      "      return null;\n"
      "    }\n"
      "  }\n"
      "  \n"
      "  function loadSponsorBlock(videoId) {\n"
      "    if (!videoId) return;\n"
      "    var tryPort = function(port) {\n"
      "      try {\n"
      "        var xhr = new XMLHttpRequest();\n"
      "        var url = 'http://127.0.0.1:' + port + '/' + encodeURIComponent(videoId);\n"
      "        xhr.timeout = 2000;\n"
      "        xhr.onload = function() {\n"
      "          if (xhr.status === 200) {\n"
      "            try {\n"
      "              var data = JSON.parse(xhr.responseText);\n"
      "              if (Array.isArray(data) && data.length > 0) {\n"
      "                sponsorSegments = data;\n"
      "                showToast('SponsorBlock', data.length + ' segment(s) found');\n"
      "              } else {\n"
      "                sponsorSegments = [];\n"
      "              }\n"
      "            } catch(e) {}\n"
      "          }\n"
      "        };\n"
      "        xhr.onerror = function() { if (port < 4050) tryPort(port + 1); };\n"
      "        xhr.ontimeout = function() { if (port < 4050) tryPort(port + 1); };\n"
      "        xhr.open('GET', url, true);\n"
      "        xhr.send();\n"
      "      } catch(e) {\n"
      "        if (port < 4050) tryPort(port + 1);\n"
      "      }\n"
      "    };\n"
      "    tryPort(4040);\n"
      "  }\n"
      "  \n"
      "  function skipAds() {\n"
      "    try {\n"
      "      var video = document.querySelector('video');\n"
      "      if (!video) return;\n"
      "      var skipBtn = document.querySelector('.ytp-ad-skip-button-modern, .ytp-ad-skip-button');\n"
      "      if (skipBtn) skipBtn.click();\n"
      "      var adContainer = document.querySelector('.ad-showing');\n"
      "      if (adContainer && video.duration && isFinite(video.duration)) {\n"
      "        video.currentTime = video.duration;\n"
      "      }\n"
      "    } catch(e) {}\n"
      "  }\n"
      "  \n"
      "  function skipSponsorSegments() {\n"
      "    try {\n"
      "      var video = document.querySelector('video');\n"
      "      if (!video || video.paused || sponsorSegments.length === 0) return;\n"
      "      var currentTime = video.currentTime;\n"
      "      for (var i = 0; i < sponsorSegments.length; i++) {\n"
      "        var seg = sponsorSegments[i].segment;\n"
      "        if (currentTime >= seg[0] && currentTime < seg[1]) {\n"
      "          video.currentTime = seg[1] + 0.1;\n"
      "          segmentsSkipped++;\n"
      "          showToast('Segment Skipped', sponsorSegments[i].category + ' (' + Math.floor(seg[1] - seg[0]) + 's)');\n"
      "          break;\n"
      "        }\n"
      "      }\n"
      "    } catch(e) {}\n"
      "  }\n"
      "  \n"
      "  function checkVideoChange() {\n"
      "    var videoId = getVideoId();\n"
      "    if (videoId && videoId !== currentVideoId) {\n"
      "      currentVideoId = videoId;\n"
      "      sponsorSegments = [];\n"
      "      segmentsSkipped = 0;\n"
      "      loadSponsorBlock(videoId);\n"
      "    }\n"
      "  }\n"
      "  \n"
      "  setInterval(skipAds, 50);\n"
      "  setInterval(skipSponsorSegments, 500);\n"
      "  setInterval(checkVideoChange, 1000);\n"
      "  checkVideoChange();\n"
      "})();\n";

  g_js_payload.assign(kHardcodedJs, kHardcodedJs + sizeof(kHardcodedJs) - 1);
  g_js_payload_loaded = true;
  MH_LOG("[execute.inject] loaded hardcoded payload %zu bytes", g_js_payload.size());
  return true;
}

const std::string& get_js_payload() {
  return g_js_payload;
}

void reset_js_payload_state() {
  g_js_payload.clear();
  g_js_payload_loaded = false;
}

void clear_script_cache() {
  // Empty stub - kept for API compatibility
}

void clear_context_tracking() {
  // Empty stub - kept for API compatibility
}

static uint32_t pattern_to_byte(const char* pattern, uint8_t* bytes) {
  uint32_t count = 0;
  const char* start = pattern;
  const char* end = pattern + strlen(pattern);

  for (const char* current = start; current < end; ++current) {
    if (*current == '?') {
      ++current;
      if (*current == '?') {
        ++current;
      }
      bytes[count++] = 0xff;
    } else {
      bytes[count++] = strtoul(current, (char**)&current, 16);
    }
  }
  return count;
}

uint8_t* pattern_scan(uint64_t module_base, uint32_t module_size, const char* signature) {
  if (!module_base || !module_size) {
    return nullptr;
  }

  constexpr uint32_t MAX_PATTERN_LENGTH = 256;
  uint8_t patternBytes[MAX_PATTERN_LENGTH] = {0};
  int32_t patternLength = pattern_to_byte(signature, patternBytes);

  if (!patternLength || patternLength >= MAX_PATTERN_LENGTH) {
    MH_LOG("Pattern length too large or invalid! %d", patternLength);
    return nullptr;
  }

  uint8_t* scanBytes = (uint8_t*)module_base;

  for (uint64_t i = 0; i < module_size; ++i) {
    bool found = true;
    for (int32_t j = 0; j < patternLength; ++j) {
      if (scanBytes[i + j] != patternBytes[j] && patternBytes[j] != 0xff) {
        found = false;
        break;
      }
    }
    if (found) {
      return &scanBytes[i];
    }
  }
  return nullptr;
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

  // Try common offsets for pointer+size+cap pattern
  for (size_t base = 0; base + 24 <= 0x80; base += 8) {
    if (try_pointer_and_length(base, base + 8, base + 16)) {
      return true;
    }
  }

  // Try additional specific offsets
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

  // Try fallback: scan for any pointer that points to ASCII
  for (size_t off = 0; off + sizeof(uint64_t) <= header.size(); off += sizeof(uint64_t)) {
    uint64_t maybe_ptr = read_u64(off);
    if (read_remote_ascii(maybe_ptr, 2048, out)) {
      MH_LOG("[extract.fallback] found string via pointer at offset 0x%zx -> %p len=%zu",
             off, (void*)maybe_ptr, out.size());
      if (out_layout && !out.empty()) {
        // Try to infer layout from pointer
        if (off + 24 <= header.size()) {
          uint64_t maybe_size = read_u64(off + 8);
          uint64_t maybe_cap = read_u64(off + 16);
          if (maybe_cap > 0 && maybe_cap <= (1ULL << 20) &&
              (maybe_size == 0 || (maybe_size <= (1ULL << 20) && maybe_cap >= maybe_size))) {
            out_layout->valid = true;
            out_layout->data_off = off;
            out_layout->size_off = off + 8;
            out_layout->cap_off = off + 16;
            out_layout->header_span = std::max<size_t>(0x40, off + 24);
          }
        }
      }
      return true;
    }
  }

  return false;
}
