#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <memory>
#include <array>
#include <algorithm>

#include <orbis/libkernel.h>      // sceKernelReadTsc
#include <orbis/SysUtil.h>
#include "mini_hook.h"
#include "patch.h"
#include "util.h"
#include "utils.h"

extern "C" void mh_log(const char* fmt, ...);

#define MH_LOG(fmt, ...) mh_log("[minihook] " fmt "\n", ##__VA_ARGS__)

#define HTML_EXECUTE_ADDR 0x0097fb40
#define BYPASS_CSP_ADDR   0x00479720

using ExecuteFn   = void (*)(void* self, long arg2, uint64_t arg3,
                             char is_external);
using BypassCspFn = long (*)(void* param_1,ulong param_2,long param_3,ulong param_4,int param_5);

static mh_hook_t  g_execute_hook{};
static mh_hook_t  g_csp_hook{};
static ExecuteFn  g_real_Execute   = nullptr;
static BypassCspFn g_real_BypassCsp = nullptr;

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

void dump_script_blob(const std::string& script, bool is_external, uint64_t hash) {
  if (script.empty()) {
    return;
  }

  size_t total = script.size();
  MH_LOG("[execute.dump] %s hash=%08llx len=%zu",
         is_external ? "external" : "inline",
         static_cast<unsigned long long>(hash & 0xffffffffu), total);

  std::string preview;
  constexpr size_t kPreviewLimit = 512;
  size_t take = std::min(total, kPreviewLimit);
  for (size_t i = 0; i < take; ++i) {
    unsigned char c = static_cast<unsigned char>(script[i]);
    preview.push_back((c >= 0x20 && c < 0x7F) ? char(c) : '.');
  }
  if (take < total) {
    preview.append("\n/* truncated preview */\n");
  }
  MH_LOG("[execute.text] %s", preview.c_str());
}

}  // namespace

extern void* __mh_tramp_slot_execute;
MH_DEFINE_THUNK(execute, my_HTMLScriptExecute)

extern void* __mh_tramp_slot_csp;
MH_DEFINE_THUNK(csp, my_BypassCsp)

extern "C" void my_HTMLScriptExecute(void* self, long arg2, uint64_t arg3,
                                     char is_external) {
  void* location = reinterpret_cast<void*>(arg3);
  MH_LOG("[execute.call] self=%p arg2=%p arg3=%p external=%d", self,
         (void*)(static_cast<uintptr_t>(arg2)), location, is_external ? 1 : 0);

  if (g_direct_injection_done) {
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }

  if (is_canonical_address(static_cast<uint64_t>(arg2))) {
    log_memory_hexdump(reinterpret_cast<void*>(static_cast<uintptr_t>(arg2)), 0x80);
  }
  if (is_canonical_address(arg3)) {
    log_memory_hexdump(reinterpret_cast<void*>(static_cast<uintptr_t>(arg3)), 0x40);
  }

  std::string active_script;
  bool have_active = false;
  StringLikeLayout learned{};
  uint64_t hash = 0;

  if (try_extract_script_from_candidate(static_cast<uint64_t>(arg2), active_script, &learned)) {
    have_active = !active_script.empty();
    MH_LOG("[extract] from arg2=%p learned.valid=%d len=%zu", (void*)static_cast<uintptr_t>(arg2), learned.valid ? 1 : 0, active_script.size());
  } else if (try_extract_script_from_candidate(arg3, active_script, &learned)) {
    have_active = !active_script.empty();
    MH_LOG("[extract] from arg3=%p learned.valid=%d len=%zu", (void*)arg3, learned.valid ? 1 : 0, active_script.size());
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
  } else {
    MH_LOG("[extract] no layout learned, g_layout.valid=%d", g_layout.valid ? 1 : 0);
  }

  if (!have_active && lookup_script_source(self, active_script)) {
    have_active = true;
  }

  // Inject on ANY script (no trigger pattern check)

  if (have_active && !active_script.empty()) {
    log_preview_bounded(reinterpret_cast<const uint8_t*>(active_script.data()),
                        active_script.size(), 96);
    if (cache_script_source(self, active_script, &hash)) {
      dump_script_blob(active_script, is_external, hash);
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
    if (try_extract_script_from_candidate(header_addr, fallback_script, &layout)) {
      if (!have_active || active_script.empty()) {
        active_script = fallback_script;
        have_active = !active_script.empty();
      }
    }
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
                 is_external);
  g_execute_reentry = false;
  g_direct_injection_done = true;
  MH_LOG("[inject.exec] mode=direct");
  MH_LOG("[inject] direct call ok");
  return;
}
extern "C" long my_BypassCsp(void* param_1,ulong param_2,long param_3,ulong param_4,int param_5) {
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

  g_direct_injection_done = false;

  patch_unsafe_inline_assignment();
  return 0;
}

extern "C" s32 attr_public plugin_unload(s32, const char**) {
  mh_remove(&g_execute_hook);
  g_real_Execute = nullptr;
  mh_remove(&g_csp_hook);
  g_real_BypassCsp = nullptr;

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
