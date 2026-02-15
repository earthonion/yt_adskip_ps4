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
#include <sys/mman.h>
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

// Signature for HTMLScriptExecute function from Ghidra
#define HTML_EXECUTE_SIG "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC D8 00 00 00 49 89 D5 48 8B 15 ?? ?? ?? ?? 48 8B 02 48 89 45 D0 80 BF 10 05 00 00 00"
#define HTML_EXECUTE_SIG_OFFSET 0
#define HTML_EXECUTE_ADDR_FALLBACK 0x0097fb40

using ExecuteFn   = void (*)(void* self, long arg2, uint64_t arg3,
                             char is_external);

static mh_hook_t  g_execute_hook{};
static ExecuteFn  g_real_Execute   = nullptr;
static void*      g_ret_gadget     = nullptr;

static thread_local bool g_execute_reentry = false;

struct LiveInjection {
  std::vector<uint8_t> header;
  std::vector<char>    payload;
};

static StringLikeLayout g_layout{};
static std::vector<std::unique_ptr<LiveInjection>> g_live_injections;
static bool g_direct_injection_done = false;
static int g_hook_call_count = 0;

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

extern "C" void my_HTMLScriptExecute(void* self, long arg2, uint64_t arg3,
                                     char is_external) {
  g_hook_call_count++;
  mh_log("[hook] ENTER #%d self=%p arg2=0x%lx arg3=0x%lx ext=%d\n",
         g_hook_call_count, self, (unsigned long)arg2, (unsigned long)arg3,
         is_external ? 1 : 0);

  // Always redirect thunk's post-callback JMP to ret gadget
  // so it doesn't double-execute the original function.
  __mh_tramp_slot_execute = g_ret_gadget;

  // After injection is done, just pass through to original.
  if (g_direct_injection_done) {
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }

  // --- Injection path (first call only) ---

  // Try to learn the string layout from args
  StringLikeLayout learned{};
  std::string temp_script;

  if (try_extract_script_from_candidate(static_cast<uint64_t>(arg2), temp_script, &learned)) {
    mh_log("[hook] extracted from arg2, learned.valid=%d len=%zu\n",
           learned.valid ? 1 : 0, temp_script.size());
  } else if (try_extract_script_from_candidate(arg3, temp_script, &learned)) {
    mh_log("[hook] extracted from arg3, learned.valid=%d len=%zu\n",
           learned.valid ? 1 : 0, temp_script.size());
  } else {
    mh_log("[hook] extract failed for both args\n");
  }

  if (learned.valid) {
    g_layout = learned;
    mh_log("[hook] layout: data@+0x%zx size@+0x%zx cap@+0x%zx\n",
           g_layout.data_off, g_layout.size_off, g_layout.cap_off);
  }

  uint64_t header_addr = 0;
  if (is_canonical_address(static_cast<uint64_t>(arg2))) {
    header_addr = static_cast<uint64_t>(arg2);
  } else if (is_canonical_address(arg3)) {
    header_addr = arg3;
  }
  if (!header_addr) {
    mh_log("[hook] BAIL: no canonical header addr\n");
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }

  if (!ensure_js_payload_loaded()) {
    mh_log("[hook] BAIL: payload unavailable\n");
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }

  const std::string& payload = get_js_payload();
  if (payload.empty()) {
    mh_log("[hook] BAIL: payload empty\n");
    g_execute_reentry = true;
    g_real_Execute(self, arg2, arg3, is_external);
    g_execute_reentry = false;
    return;
  }
  mh_log("[hook] payload loaded, %zu bytes\n", payload.size());

  StringLikeLayout layout = learned.valid ? learned : g_layout;
  if (!layout.valid) {
    std::string fallback_script;
    try_extract_script_from_candidate(header_addr, fallback_script, &layout);
    mh_log("[hook] fallback extract: valid=%d\n", layout.valid ? 1 : 0);
  }

  constexpr size_t kProbe = 0x80;
  std::array<uint8_t, kProbe> header{};
  sys_proc_ro(header_addr, header.data(), header.size());

  bool layout_span_ok = layout.valid &&
                        layout.data_off + sizeof(uint64_t) <= header.size() &&
                        layout.size_off + sizeof(uint64_t) <= header.size() &&
                        layout.cap_off  + sizeof(uint64_t) <= header.size();
  if (!layout_span_ok) {
    mh_log("[hook] BAIL: layout invalid (valid=%d d=0x%zx s=0x%zx c=0x%zx)\n",
           layout.valid ? 1 : 0, layout.data_off, layout.size_off, layout.cap_off);
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

  // Build cloned header with our payload swapped in
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
  g_live_injections.push_back(std::move(storage));

  mh_log("[hook] INJECTING payload=%zu bytes header=%p\n",
         payload.size(), cloned_header);

  // Delay before injection so the Cobalt engine can settle
  sceKernelUsleep(3 * 1000 * 1000);

  // Execute our injected JS payload (same approach as working GitHub version)
  g_execute_reentry = true;
  g_real_Execute(self,
                 static_cast<long>(reinterpret_cast<uintptr_t>(cloned_header)),
                 arg3,
                 0);  // is_external=0 → trusted/internal script
  g_execute_reentry = false;

  g_direct_injection_done = true;
  mh_log("[hook] INJECT OK — JS executed, slot switched to ret gadget\n");

  // Note: thunk's tramp_slot was set to ret_gadget at the top of this function.
  // When we return, the thunk will JMP to the ret gadget (just a RET instruction)
  // instead of jumping to the trampoline. This prevents double-execution.
  // The original script for this first call does NOT run — only our injected JS.
  // All subsequent calls (g_direct_injection_done=true) run the original once.
  return;
}

extern "C" s32 attr_public plugin_load(s32, const char**) {
  int r = 0;

  // Get main module info
  OrbisKernelModuleInfo moduleInfo;
  memset(&moduleInfo, 0, sizeof(moduleInfo));
  moduleInfo.size = sizeof(moduleInfo);

  OrbisKernelModule handles[256];
  size_t numModules;
  r = sceKernelGetModuleList(handles, sizeof(handles), &numModules);
  if (r != 0) {
    mh_log("[minihook] sceKernelGetModuleList failed: 0x%08X\n", r);
    return -1;
  }

  uint64_t module_base = 0;
  uint32_t module_size = 0;

  if (numModules > 0) {
    r = sceKernelGetModuleInfo(handles[0], &moduleInfo);
    if (r == 0) {
      mh_log("[minihook] Module: %s\n", moduleInfo.name);
      for (int seg = 0; seg < 4; seg++) {
        if (moduleInfo.segmentInfo[seg].address) {
          mh_log("[minihook]   Segment %d: addr=0x%lx size=0x%x prot=0x%x\n",
                 seg,
                 (uint64_t)moduleInfo.segmentInfo[seg].address,
                 moduleInfo.segmentInfo[seg].size,
                 moduleInfo.segmentInfo[seg].prot);
        }
      }
      module_base = (uint64_t)moduleInfo.segmentInfo[0].address;
      module_size = moduleInfo.segmentInfo[0].size;
    }
  }

  // Find HTMLScriptExecute using pattern scan
  uint64_t html_execute_addr = 0;
  if (module_base && module_size) {
    uint8_t* found = pattern_scan(module_base, module_size, HTML_EXECUTE_SIG);
    if (found) {
      html_execute_addr = (uint64_t)found + HTML_EXECUTE_SIG_OFFSET;
      mh_log("[minihook] HTMLScriptExecute found at 0x%lx\n", html_execute_addr);
    } else {
      mh_log("[minihook] Pattern scan failed, using fallback address 0x%lx\n", HTML_EXECUTE_ADDR_FALLBACK);
      html_execute_addr = HTML_EXECUTE_ADDR_FALLBACK;
    }
  } else {
    mh_log("[minihook] Failed to get module info, using fallback address 0x%lx\n", HTML_EXECUTE_ADDR_FALLBACK);
    html_execute_addr = HTML_EXECUTE_ADDR_FALLBACK;
  }

  std::memset(&g_execute_hook, 0, sizeof(g_execute_hook));
  g_execute_hook.target_addr = html_execute_addr;
  g_execute_hook.user_impl   = (void*)my_HTMLScriptExecute;
  g_execute_hook.user_thunk  = (void*)MH_THUNK_ENTRY(execute);

  r = mh_install(&g_execute_hook);
  if (r) {
    mh_log("[minihook] Hook install FAILED: %d\n", r);
    return r;
  }

  // Bind thunk slot to trampoline initially (will be switched to ret gadget
  // on first callback entry).
  mh_bind_thunk_slot(&__mh_tramp_slot_execute, g_execute_hook.tramp_mem);
  g_real_Execute = (ExecuteFn)g_execute_hook.orig_fn;

  // Prepare a RET gadget in the trampoline page (RWX).
  // We redirect the thunk's tramp_slot here so the thunk's post-callback
  // JMP becomes a no-op (just returns to caller), preventing double execution.
  uint8_t* ret_addr = (uint8_t*)g_execute_hook.tramp_mem + g_execute_hook.tramp_size;
  *ret_addr = 0xC3;  // RET
  g_ret_gadget = ret_addr;

  mh_log("[minihook] Hook installed. orig=%p tramp=%p ret=%p target=0x%lx\n",
         (void*)g_real_Execute, g_execute_hook.tramp_mem,
         g_ret_gadget, html_execute_addr);

  // Create directories
  sceKernelMkdir("/data/youtube", 0777);
  sceKernelMkdir("/data/youtube/dump", 0777);

  // Start SponsorBlock proxy server
  if (!start_sponsorblock_proxy()) {
    mh_log("[minihook] Failed to start SponsorBlock proxy\n");
  }

  g_direct_injection_done = false;
  return 0;
}

extern "C" s32 attr_public plugin_unload(s32, const char**) {
  stop_sponsorblock_proxy();

  mh_remove(&g_execute_hook);
  g_real_Execute = nullptr;

  clear_script_cache();
  clear_context_tracking();
  reset_js_payload_state();

  g_layout = {};
  g_live_injections.clear();
  g_live_injections.shrink_to_fit();
  g_direct_injection_done = false;
  mh_log("[minihook] hooks removed\n");
  return 0;
}

extern "C" s32 attr_module_hidden module_start(s64, const void*) { return 0; }
extern "C" s32 attr_module_hidden module_stop (s64, const void*) { return 0; }
