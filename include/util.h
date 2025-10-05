#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string>

struct StringLikeLayout {
  bool   valid = false;
  size_t data_off = 0;
  size_t size_off = 0;
  size_t cap_off  = 0;
  size_t header_span = 0x40;
};

bool is_canonical_address(uint64_t addr);
void log_preview_bounded(const uint8_t* b, size_t n, size_t max_chars);

bool try_extract_script_from_candidate(uint64_t candidate,
                                       std::string& out,
                                       StringLikeLayout* out_layout = nullptr);

bool ensure_js_payload_loaded();
const std::string& get_js_payload();
void reset_js_payload_state();

void clear_script_cache();
void clear_context_tracking();

uint8_t* pattern_scan(uint64_t module_base, uint32_t module_size, const char* signature);
