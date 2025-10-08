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
// 0097fb40: 55                    PUSH RBP
// 0097fb41: 48 89 E5              MOV RBP,RSP
// 0097fb44: 41 57                 PUSH R15
// 0097fb46: 41 56                 PUSH R14
// 0097fb48: 41 55                 PUSH R13
// 0097fb4a: 41 54                 PUSH R12
// 0097fb4c: 53                    PUSH RBX
// 0097fb4d: 48 81 EC D8 00 00 00  SUB RSP,0xd8
// 0097fb54: 49 89 D5              MOV R13,RDX
// 0097fb57: 48 8B 15 ?? ?? ?? ??  MOV RDX,[stack_chk_guard] (wildcard)
// 0097fb5e: 48 8B 02              MOV RAX,[RDX]
// 0097fb61: 48 89 45 D0           MOV [RBP-0x30],RAX
// 0097fb65: 80 BF 10 05 00 00 00  CMP byte ptr [RDI+0x510],0x0
#define HTML_EXECUTE_SIG "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 81 EC D8 00 00 00 49 89 D5 48 8B 15 ?? ?? ?? ?? 48 8B 02 48 89 45 D0 80 BF 10 05 00 00 00"
#define HTML_EXECUTE_SIG_OFFSET 0
#define HTML_EXECUTE_ADDR_FALLBACK 0x0097fb40

using ExecuteFn   = void (*)(void* self, long arg2, uint64_t arg3,
                             char is_external);

static mh_hook_t  g_execute_hook{};
static ExecuteFn  g_real_Execute   = nullptr;

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
    MH_LOG("sceKernelGetModuleList failed: 0x%08X", r);
    return -1;
  }

  uint64_t module_base = 0;
  uint32_t module_size = 0;

  // Get first module (main executable) - need to find the TEXT segment
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
      // Use first segment (should be TEXT segment with executable code)
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
    MH_LOG("[hook] Execute install FAILED %d", r);
    return r;
  }

  mh_bind_thunk_slot(&__mh_tramp_slot_execute, g_execute_hook.tramp_mem);
  g_real_Execute = (ExecuteFn)g_execute_hook.orig_fn;
  MH_LOG("[hook] Execute installed. orig=%p tramp=%p target=%p",
         (void*)g_real_Execute, g_execute_hook.tramp_mem,
         (void*)html_execute_addr);

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
