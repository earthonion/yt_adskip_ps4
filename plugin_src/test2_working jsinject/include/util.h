#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

struct HashRing {
  bool seen(uint64_t hash);

private:
  static constexpr size_t kCapacity = 64;
  uint64_t values_[kCapacity] = {};
  size_t next_ = 0;
};

struct StringLikeLayout {
  bool   valid = false;
  size_t data_off = 0;
  size_t size_off = 0;
  size_t cap_off  = 0;
  size_t header_span = 0x40;
};

uint64_t fnv1a64(const void* data, size_t len);

bool looks_printable_text(const uint8_t* data, size_t len, double min_ratio = 0.85);
const char* infer_ext(const uint8_t* data, size_t len);
bool looks_interesting(const uint8_t* data, size_t len);

size_t find_substring(const char* haystack, size_t hay_len, const char* needle);
size_t find_last_substring(const char* haystack, size_t hay_len, const char* needle);

bool is_canonical_address(uint64_t addr);
void log_memory_hexdump(const void* addr, size_t bytes);
void log_preview_bounded(const uint8_t* b, size_t n, size_t max_chars);

bool buffer_has_anchor(const char* data, size_t len);

bool try_extract_script_from_candidate(uint64_t candidate,
                                       std::string& out,
                                       StringLikeLayout* out_layout = nullptr);

bool ensure_js_payload_loaded();
const std::string& get_js_payload();
void reset_js_payload_state();

bool write_payload_to_remote(uint64_t remote_data_ptr,
                             uint64_t header_addr,
                             const StringLikeLayout& layout,
                             const std::string& payload,
                             uint64_t remote_cap,
                             uint64_t original_size);

bool cache_script_source(void* self, const std::string& script,
                         uint64_t* out_hash = nullptr);
bool lookup_script_source(void* self, std::string& out);
void clear_script_cache();

bool context_already_injected(void* context);
void remember_context(void* context);
void clear_context_tracking();

void patch_unsafe_inline_assignment();
