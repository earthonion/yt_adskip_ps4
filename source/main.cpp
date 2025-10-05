#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <string>
#include <vector>
#include <memory>
#include <array>
#include <algorithm>

#include <orbis/libkernel.h>
#include <orbis/Http.h>
#include <orbis/Ssl.h>
#include <orbis/Net.h>
#include "mini_hook.h"
#include "patch.h"
#include "util.h"
#include "proxy.h"

extern "C" void mh_log(const char* fmt, ...);

#ifdef __DEBUG_LOG__
#define MH_LOG(fmt, ...) mh_log("[minihook] " fmt "\n", ##__VA_ARGS__)
#else
#define MH_LOG(fmt, ...) ((void)0)
#endif

#define HTML_EXECUTE_ADDR 0x0097fb40
#define BYPASS_CSP_ADDR   0x014100f0
#define CSP_PARSE_ADDR    0x009e27c0
#define CSP_DIRECTIVE_ADDR 0x009e36f0
#define DOMAIN_WHITELIST_ADDR 0x00446be0
#define STATUS_CHECK_ADDR 0x015bffa0
#define XHR_INNER_CHECK_ADDR 0x00ab7180

using ExecuteFn   = void (*)(void* self, long arg2, uint64_t arg3,
                             char is_external);
using BypassCspFn = void (*)(long param_1);
using CspParseFn = void (*)(long* param_1, long param_2, long param_3);
using CspDirectiveFn = void (*)(uint64_t* param_1, uint64_t param_2, uint64_t param_3, long* param_4);
using DomainWhitelistFn = uint64_t (*)(long param_1);
using StatusCheckFn = uint32_t (*)(long param_1);
using XhrInnerCheckFn = char (*)(uint64_t param_1, long* param_2);

static mh_hook_t  g_execute_hook{};
static mh_hook_t  g_csp_hook{};
static mh_hook_t  g_csp_parse_hook{};
static mh_hook_t  g_csp_directive_hook{};
static mh_hook_t  g_domain_whitelist_hook{};
static mh_hook_t  g_status_check_hook{};
static mh_hook_t  g_xhr_inner_check_hook{};
static ExecuteFn  g_real_Execute   = nullptr;
static BypassCspFn g_real_BypassCsp = nullptr;
static CspParseFn g_real_CspParse = nullptr;
static CspDirectiveFn g_real_CspDirective = nullptr;
static DomainWhitelistFn g_real_DomainWhitelist = nullptr;
static StatusCheckFn g_real_StatusCheck = nullptr;
static XhrInnerCheckFn g_real_XhrInnerCheck = nullptr;

static thread_local bool g_execute_reentry = false;

struct LiveInjection {
  std::vector<uint8_t> header;
  std::vector<char>    payload;
};

static StringLikeLayout g_layout{};
static std::vector<std::unique_ptr<LiveInjection>> g_live_injections;
static bool g_direct_injection_done = false;

namespace {

void ensure_live_injection_budget() {
  constexpr size_t kMaxLive = 32;
  if (g_live_injections.size() >= kMaxLive) {
    g_live_injections.erase(g_live_injections.begin());
  }
}

}  // namespace

extern void* __mh_tramp_slot_execute;
MH_DEFINE_THUNK(execute, my_HTMLScriptExecute)

extern void* __mh_tramp_slot_csp;
MH_DEFINE_THUNK(csp, my_BypassCsp)

extern void* __mh_tramp_slot_csp_parse;
MH_DEFINE_THUNK(csp_parse, my_CspParse)

extern void* __mh_tramp_slot_csp_directive;
MH_DEFINE_THUNK(csp_directive, my_CspDirective)

extern void* __mh_tramp_slot_domain_whitelist;
MH_DEFINE_THUNK(domain_whitelist, my_DomainWhitelist)

extern void* __mh_tramp_slot_xhr_inner_check;
MH_DEFINE_THUNK(xhr_inner_check, my_XhrInnerCheck)

extern "C" void my_HTMLScriptExecute(void* self, long arg2, uint64_t arg3,
                                     char is_external) {
  MH_LOG("[execute.call] self=%p arg2=%p arg3=%p external=%d", self,
         (void*)(static_cast<uintptr_t>(arg2)), (void*)arg3, is_external ? 1 : 0);

  if (g_direct_injection_done) {
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }

  StringLikeLayout learned{};
  std::string temp_script;

  if (try_extract_script_from_candidate(static_cast<uint64_t>(arg2), temp_script, &learned)) {
    MH_LOG("[extract] from arg2=%p learned.valid=%d", (void*)static_cast<uintptr_t>(arg2), learned.valid ? 1 : 0);
  } else if (try_extract_script_from_candidate(arg3, temp_script, &learned)) {
    MH_LOG("[extract] from arg3=%p learned.valid=%d", (void*)arg3, learned.valid ? 1 : 0);
  }

  if (learned.valid) {
    bool changed = !g_layout.valid || g_layout.data_off != learned.data_off ||
                   g_layout.size_off != learned.size_off ||
                   g_layout.cap_off  != learned.cap_off;
    g_layout = learned;
    if (changed) {
      MH_LOG("[layout] data@+0x%zx size@+0x%zx cap@+0x%zx span=0x%zx",
             g_layout.data_off, g_layout.size_off, g_layout.cap_off, g_layout.header_span);
    }
  }

  uint64_t header_addr = 0;
  if (is_canonical_address(static_cast<uint64_t>(arg2))) {
    header_addr = static_cast<uint64_t>(arg2);
  } else if (is_canonical_address(arg3)) {
    header_addr = arg3;
  }
  if (!header_addr) {
    MH_LOG("[inject.err] reason=no-header");
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }

  if (!ensure_js_payload_loaded()) {
    MH_LOG("[execute.inject] payload unavailable");
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }

  const std::string& payload = get_js_payload();
  if (payload.empty()) {
    MH_LOG("[execute.inject] payload empty after normalization");
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }

  StringLikeLayout layout = learned.valid ? learned : g_layout;
  if (!layout.valid) {
    std::string fallback_script;
    try_extract_script_from_candidate(header_addr, fallback_script, &layout);
  }

  constexpr size_t kProbe = 0x80;
  std::array<uint8_t, kProbe> header{};
  sys_proc_ro(header_addr, header.data(), header.size());

  bool layout_span_ok = layout.valid &&
                        layout.data_off + sizeof(uint64_t) <= header.size() &&
                        layout.size_off + sizeof(uint64_t) <= header.size() &&
                        layout.cap_off  + sizeof(uint64_t) <= header.size();
  if (!layout_span_ok) {
    MH_LOG("[inject.err] reason=layout-span");
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }
  g_layout = layout;

  if (g_execute_reentry) {
    g_real_Execute(self, arg2, arg3, is_external);
    return;
  }

  ensure_live_injection_budget();
  auto storage = std::make_unique<LiveInjection>();
  storage->header.assign(header.begin(), header.end());
  storage->payload.assign(payload.begin(), payload.end());

  auto write_u64_header = [&](size_t off, uint64_t value) {
    if (off + sizeof(uint64_t) <= storage->header.size()) {
      std::memcpy(storage->header.data() + off, &value, sizeof(uint64_t));
    }
  };

  uint64_t payload_ptr = reinterpret_cast<uint64_t>(storage->payload.data());
  write_u64_header(layout.data_off, payload_ptr);
  write_u64_header(layout.size_off, static_cast<uint64_t>(storage->payload.size()));
  write_u64_header(layout.cap_off,
                   static_cast<uint64_t>(std::max<size_t>(storage->payload.size(), 0x10)));

  void* cloned_header = storage->header.data();
  log_preview_bounded(reinterpret_cast<const uint8_t*>(storage->payload.data()),
                      storage->payload.size(), 96);
  MH_LOG("[inject.direct] len=%zu header=%p data=%p",
         storage->payload.size(), cloned_header, storage->payload.data());

  g_live_injections.push_back(std::move(storage));

  // delay before invoking Execute so the target can settle
  sceKernelUsleep(3 * 1000 * 1000);

  g_execute_reentry = true;
  g_real_Execute(self,
                 static_cast<long>(reinterpret_cast<uintptr_t>(cloned_header)),
                 arg3,
                 0);  // Force is_external=0 to mark as trusted/internal script
  g_execute_reentry = false;
  g_direct_injection_done = true;
  MH_LOG("[inject.exec] mode=direct");
  MH_LOG("[inject] direct call ok");
  return;
}
extern "C" void my_BypassCsp(long param_1) {
  // Hook CSP event handler registration - do nothing to prevent CSP from being enforced
  MH_LOG("[csp] CSP event handler registration blocked");
  return;
}

extern "C" void my_CspParse(long* param_1, long param_2, long param_3) {
  // Call original parser - we'll handle connect-src specifically in directive hook
  g_real_CspParse(param_1, param_2, param_3);
}

extern "C" void my_CspDirective(uint64_t* param_1, uint64_t param_2, uint64_t param_3, long* param_4) {
  // Check multiple possible offsets for connect-src
  bool is_connect_src_1 = (param_4 == (long*)(param_1 + 0x10));
  bool is_connect_src_2 = (param_4 == (long*)(param_1 + 0x02));
  bool is_connect_src_3 = (param_4 == (long*)(param_1 + 0x08));

  if (is_connect_src_1 || is_connect_src_2 || is_connect_src_3) {
    MH_LOG("[csp-directive] SKIPPING connect-src (offset match: %d/%d/%d)",
           is_connect_src_1, is_connect_src_2, is_connect_src_3);
    return;  // Don't create the connect-src policy
  }

  // For other directives, call original
  g_real_CspDirective(param_1, param_2, param_3, param_4);
}

extern "C" uint64_t my_DomainWhitelist(long param_1) {
  static uint64_t cached_allowed_result = 0;

  // Call original
  uint64_t original_result = g_real_DomainWhitelist(param_1);

  // If it's already allowed (non-zero), cache it and return it
  if (original_result != 0) {
    cached_allowed_result = original_result;
    MH_LOG("[domain-whitelist] Allowed: %llu", (unsigned long long)original_result);
    return original_result;
  }

  // If blocked (0) and we have a cached allowed result, use that
  if (cached_allowed_result != 0) {
    MH_LOG("[domain-whitelist] BLOCKED->Spoofing with cached: %llu",
           (unsigned long long)cached_allowed_result);
    return cached_allowed_result;
  }

  // No cached result yet, return original (will block but we'll get a cache soon)
  MH_LOG("[domain-whitelist] Blocked (no cache yet)");
  return original_result;
}

extern "C" char my_StatusCheck(long param_1) {
  // Always return 1 to pass the status check
  MH_LOG("[status-check] Forcing return 1");
  return 1;
}

extern "C" char my_XhrInnerCheck(uint64_t param_1, long* param_2) {
  // Call original security check first
  if (!g_real_XhrInnerCheck) {
    return 1;  // Fallback if not initialized
  }

  char result = g_real_XhrInnerCheck(param_1, param_2);

  // If original allows it, return that
  if (result == 1) {
    return result;
  }

  // Original blocked it - override to allow (for SponsorBlock API)
  // No logging - called too frequently
  return 1;
}

extern "C" s32 attr_public plugin_load(s32, const char**) {
  int r = 0;

  std::memset(&g_execute_hook, 0, sizeof(g_execute_hook));
  g_execute_hook.target_addr = HTML_EXECUTE_ADDR;
  g_execute_hook.user_impl   = (void*)my_HTMLScriptExecute;
  g_execute_hook.user_thunk  = (void*)MH_THUNK_ENTRY(execute);

  r = mh_install(&g_execute_hook);
  if (r) {
    MH_LOG("[hook] Execute install FAILED %d", r);
    return r;
  }

  mh_bind_thunk_slot(&__mh_tramp_slot_execute, g_execute_hook.tramp_mem);
  g_real_Execute = (ExecuteFn)g_execute_hook.orig_fn;
  MH_LOG("[hook] Execute installed. orig=%p tramp=%p target=%p",
         (void*)g_real_Execute, g_execute_hook.tramp_mem,
         (void*)HTML_EXECUTE_ADDR);

  std::memset(&g_csp_hook, 0, sizeof(g_csp_hook));
  g_csp_hook.target_addr = BYPASS_CSP_ADDR;
  g_csp_hook.user_impl   = (void*)my_BypassCsp;
  g_csp_hook.user_thunk  = (void*)MH_THUNK_ENTRY(csp);

  r = mh_install(&g_csp_hook);
  if (r) {
    MH_LOG("[hook] BypassCSP install FAILED %d", r);
    mh_remove(&g_execute_hook);
    g_real_Execute = nullptr;
    return r;
  }
  mh_bind_thunk_slot(&__mh_tramp_slot_csp, g_csp_hook.tramp_mem);
  g_real_BypassCsp = (BypassCspFn)g_csp_hook.orig_fn;
  MH_LOG("[hook] BypassCSP installed. orig=%p tramp=%p target=%p",
         (void*)g_real_BypassCsp, g_csp_hook.tramp_mem,
         (void*)BYPASS_CSP_ADDR);

  std::memset(&g_csp_parse_hook, 0, sizeof(g_csp_parse_hook));
  g_csp_parse_hook.target_addr = CSP_PARSE_ADDR;
  g_csp_parse_hook.user_impl   = (void*)my_CspParse;
  g_csp_parse_hook.user_thunk  = (void*)MH_THUNK_ENTRY(csp_parse);

  r = mh_install(&g_csp_parse_hook);
  if (r) {
    MH_LOG("[hook] CspParse install FAILED %d", r);
    mh_remove(&g_csp_hook);
    g_real_BypassCsp = nullptr;
    mh_remove(&g_execute_hook);
    g_real_Execute = nullptr;
    return r;
  }
  mh_bind_thunk_slot(&__mh_tramp_slot_csp_parse, g_csp_parse_hook.tramp_mem);
  g_real_CspParse = (CspParseFn)g_csp_parse_hook.orig_fn;
  MH_LOG("[hook] CspParse installed. orig=%p tramp=%p target=%p",
         (void*)g_real_CspParse, g_csp_parse_hook.tramp_mem,
         (void*)CSP_PARSE_ADDR);

  std::memset(&g_csp_directive_hook, 0, sizeof(g_csp_directive_hook));
  g_csp_directive_hook.target_addr = CSP_DIRECTIVE_ADDR;
  g_csp_directive_hook.user_impl   = (void*)my_CspDirective;
  g_csp_directive_hook.user_thunk  = (void*)MH_THUNK_ENTRY(csp_directive);

  r = mh_install(&g_csp_directive_hook);
  if (r) {
    MH_LOG("[hook] CspDirective install FAILED %d", r);
    mh_remove(&g_csp_parse_hook);
    g_real_CspParse = nullptr;
    mh_remove(&g_csp_hook);
    g_real_BypassCsp = nullptr;
    mh_remove(&g_execute_hook);
    g_real_Execute = nullptr;
    return r;
  }
  mh_bind_thunk_slot(&__mh_tramp_slot_csp_directive, g_csp_directive_hook.tramp_mem);
  g_real_CspDirective = (CspDirectiveFn)g_csp_directive_hook.orig_fn;
  MH_LOG("[hook] CspDirective installed. orig=%p tramp=%p target=%p",
         (void*)g_real_CspDirective, g_csp_directive_hook.tramp_mem,
         (void*)CSP_DIRECTIVE_ADDR);

  std::memset(&g_domain_whitelist_hook, 0, sizeof(g_domain_whitelist_hook));
  g_domain_whitelist_hook.target_addr = DOMAIN_WHITELIST_ADDR;
  g_domain_whitelist_hook.user_impl   = (void*)my_DomainWhitelist;
  g_domain_whitelist_hook.user_thunk  = (void*)MH_THUNK_ENTRY(domain_whitelist);

  r = mh_install(&g_domain_whitelist_hook);
  if (r) {
    MH_LOG("[hook] DomainWhitelist install FAILED %d", r);
    mh_remove(&g_csp_directive_hook);
    g_real_CspDirective = nullptr;
    mh_remove(&g_csp_parse_hook);
    g_real_CspParse = nullptr;
    mh_remove(&g_csp_hook);
    g_real_BypassCsp = nullptr;
    mh_remove(&g_execute_hook);
    g_real_Execute = nullptr;
    return r;
  }
  mh_bind_thunk_slot(&__mh_tramp_slot_domain_whitelist, g_domain_whitelist_hook.tramp_mem);
  g_real_DomainWhitelist = (DomainWhitelistFn)g_domain_whitelist_hook.orig_fn;
  MH_LOG("[hook] DomainWhitelist installed. orig=%p tramp=%p target=%p",
         (void*)g_real_DomainWhitelist, g_domain_whitelist_hook.tramp_mem,
         (void*)DOMAIN_WHITELIST_ADDR);

  // Install status check hook in wrapper mode (no trampoline needed)
  std::memset(&g_status_check_hook, 0, sizeof(g_status_check_hook));
  g_status_check_hook.target_addr = STATUS_CHECK_ADDR;
  g_status_check_hook.user_impl   = (void*)my_StatusCheck;
  g_status_check_hook.user_thunk  = nullptr;  // Wrapper mode

  r = mh_install(&g_status_check_hook);
  if (r) {
    MH_LOG("[hook] StatusCheck install FAILED %d", r);
  } else {
    MH_LOG("[hook] StatusCheck installed (wrapper mode)");
  }

  // XHR inner check hook disabled - too invasive, causes crashes
  // The domain whitelist + CSP hooks should be sufficient for SponsorBlock

  // Start SponsorBlock proxy server
  if (!start_sponsorblock_proxy()) {
    MH_LOG("[proxy] Failed to start SponsorBlock proxy");
  }

  g_direct_injection_done = false;
  return 0;
}

extern "C" s32 attr_public plugin_unload(s32, const char**) {
  // Stop proxy server
  stop_sponsorblock_proxy();

  mh_remove(&g_execute_hook);
  g_real_Execute = nullptr;
  mh_remove(&g_csp_hook);
  g_real_BypassCsp = nullptr;
  mh_remove(&g_csp_parse_hook);
  g_real_CspParse = nullptr;
  mh_remove(&g_csp_directive_hook);
  g_real_CspDirective = nullptr;
  mh_remove(&g_domain_whitelist_hook);
  g_real_DomainWhitelist = nullptr;
  mh_remove(&g_status_check_hook);
  g_real_StatusCheck = nullptr;
  mh_remove(&g_xhr_inner_check_hook);
  g_real_XhrInnerCheck = nullptr;

  clear_script_cache();
  clear_context_tracking();
  reset_js_payload_state();

  g_layout = {};
  g_live_injections.clear();
  g_live_injections.shrink_to_fit();
  g_direct_injection_done = false;
  MH_LOG("[hook] hooks removed");
  return 0;
}

extern "C" s32 attr_module_hidden module_start(s64, const void*) { return 0; }
extern "C" s32 attr_module_hidden module_stop (s64, const void*) { return 0; }
