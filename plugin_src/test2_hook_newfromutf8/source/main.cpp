#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>
#include <errno.h>

#include <orbis/libkernel.h>      // sceKernelReadTsc
#include "mini_hook.h"            // mh_* API from your project
#include "util.h"

// ---------------------------------------------------------
// Logging (provided by your env)
// ---------------------------------------------------------
extern "C" void mh_log(const char* fmt, ...);

#define MH_LOG(fmt, ...) mh_log("[minihook] " fmt "\n", ##__VA_ARGS__)

// ---------------------------------------------------------
// Helpers
// ---------------------------------------------------------

static void dump_hex_block(const uint8_t* buf, size_t len, size_t width = 16) {
  char line[512];
  for (size_t i = 0; i < len; i += width) {
    size_t pos = 0;
    pos += snprintf(line + pos, sizeof(line) - pos, "[utf8.hex] %04zx :", i);
    for (size_t j = 0; j < width && (i + j) < len; j++) {
      pos += snprintf(line + pos, sizeof(line) - pos, " %02X", buf[i + j]);
    }
    // ASCII tail
    pos += snprintf(line + pos, sizeof(line) - pos, "  ");
    for (size_t j = 0; j < width && (i + j) < len; j++) {
      unsigned c = buf[i + j];
      line[pos++] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
      if (pos >= sizeof(line) - 2) break;
    }
    line[pos] = '\0';
    MH_LOG("%s", line);
  }
}


// ---------- tiny utils

static HashRing g_seen_utf8;

#define NEWFROMUTF8_ADDR 0x00ab73c0
#define BYPASS_CSP_ADDR 0x00446be0

using NewFromUtf8Fn = long(*)(long isolate, char* data, int type, int size);
using BypassCspFn    = long(*)(long arg);

static mh_hook_t     g_utf8_hook{};
static NewFromUtf8Fn g_real_NewFromUtf8 = nullptr;
static mh_hook_t     g_csp_hook{};
static BypassCspFn   g_real_BypassCsp   = nullptr;

// optional: capture a rough callsite (return address of caller)
static inline __attribute__((unused)) uintptr_t callsite() {
#if defined(__GNUC__)
  return (uintptr_t)__builtin_return_address(0);
#else
  return 0;
#endif
}

static void patch_unsafe_inline_assignment() {
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

static constexpr const char* kInjectFilePath = "/data/inject.js";
static const char kDefaultPayload[] = R"JS(
(function () {
  if (typeof document === 'undefined') {
    return;
  }

  function ensureBanner() {
    if (typeof document === 'undefined') {
      return;
    }
    var body = document.body;
    if (!body) {
      if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(ensureBanner, { timeout: 1000 });
      } else {
        setTimeout(ensureBanner, 50);
      }
      return;
    }

    if (document.getElementById('minihook-banner')) {
      return;
    }

    var banner = document.createElement('div');
    banner.id = 'minihook-banner';
    banner.textContent = 'injected!';
    banner.style.position = 'fixed';
    banner.style.top = '8px';
    banner.style.left = '8px';
    banner.style.padding = '6px 12px';
    banner.style.background = 'rgba(22, 22, 22, 0.85)';
    banner.style.color = '#00ffcc';
    banner.style.font = '14px/1.3 "Segoe UI", Arial, sans-serif';
    banner.style.borderRadius = '4px';
    banner.style.zIndex = '2147483647';
    banner.style.boxShadow = '0 2px 6px rgba(0,0,0,0.35)';
    banner.style.pointerEvents = 'none';
    body.appendChild(banner);
    setTimeout(function () {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    }, 4000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ensureBanner, { once: true });
  } else {
    ensureBanner();
  }
})();
)JS";

static std::string g_js_payload;
static bool g_js_payload_loaded = false;
static bool g_js_payload_failed = false;

struct InjectResult {
  bool handled;
  long value;
};

static bool ensure_js_payload_loaded();
static InjectResult try_inject_script(long isolate, char* data, size_t eff_len, int type);

// dump helper that appends a sensible extension + short hash
static __attribute__((unused)) void dump_blob_with_ext(const uint8_t* data, size_t len,
                                uintptr_t cs) {
  const char* ext = infer_ext(data, len);
  uint64_t h = fnv1a64(data, len);
  char path[256];
  uint64_t tsc = sceKernelReadTsc();
  // include a short hash and callsite to make filenames stable-ish
  snprintf(path, sizeof(path),
           "/data/youtube/exec_utf8_%016llx_cs%llx_%llu%s",
           (unsigned long long)h,
           (unsigned long long)cs,
           (unsigned long long)tsc,
           ext);
  FILE* f = fopen(path, "wb");
  if (!f) { MH_LOG("[utf8.dump] fopen failed: %s", path); return; }
  fwrite(data, 1, len, f);
  fclose(f);
  MH_LOG("[utf8.dump] wrote %zu/%zu bytes -> %s", len, len, path);
}

static void log_preview_bounded(const uint8_t* b, size_t n, size_t max_chars) {
  size_t take = n < max_chars ? n : max_chars;
  // Build a sanitized, NUL-terminated preview.
  char buf[256 + 1];
  if (take > 256) take = 256;
  for (size_t i = 0; i < take; ++i) {
    uint8_t c = b[i];
    buf[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
  }
  buf[take] = 0;
  MH_LOG("[utf8.preview 0..%zu] %s", take, buf);
}

static __attribute__((unused)) void
dump_blob_safely(const uint8_t* data, size_t len, const char* tag,
                 const char* forced_ext = nullptr) {
  const char* ext = forced_ext ? forced_ext : infer_ext(data, len);
  uint64_t tsc = sceKernelReadTsc();
  char path[256];
  // ext is one of our literals (".js", ".json", ".txt", ".bin")
  snprintf(path, sizeof(path), "/data/youtube/exec_utf8_%s_%llu%s",
           tag, (unsigned long long)tsc, ext);

  FILE* f = fopen(path, "wb");
  if (!f) { MH_LOG("[utf8.dump] fopen failed: %s", path); return; }
  size_t wrote = fwrite(data, 1, len, f);
  fclose(f);
  MH_LOG("[utf8.dump] wrote %zu/%zu bytes -> %s", wrote, len, path);
}


static __attribute__((unused)) void dump_to_file(const void* data, size_t len, const char* tag) {
  char path[256];
  unsigned long long tsc = (unsigned long long) sceKernelReadTsc();
  snprintf(path, sizeof(path), "/data/youtube/exec_utf8_%s_%llu.bin", tag, tsc);

  FILE* f = fopen(path, "wb");
  if (!f) {
    MH_LOG("[utf8.dump] fopen failed: %s", path);
    return;
  }
  size_t wrote = fwrite(data, 1, len, f);
  fclose(f);
  MH_LOG("[utf8.dump] wrote %zu/%zu bytes -> %s", wrote, len, path);
}

static bool ensure_js_payload_loaded() {
  if (g_js_payload_loaded) {
    return true;
  }
  if (g_js_payload_failed) {
    return false;
  }

  FILE* f = fopen(kInjectFilePath, "rb");
  if (!f) {
    g_js_payload.assign(kDefaultPayload, sizeof(kDefaultPayload) - 1);
    g_js_payload_loaded = true;
    MH_LOG("[utf8.inject] %s missing; using default payload (%zu bytes)",
           kInjectFilePath, g_js_payload.size());
    return true;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    int err = errno;
    MH_LOG("[utf8.inject] fseek end failed (%d: %s)", err, strerror(err));
    fclose(f);
    g_js_payload_failed = true;
    return false;
  }

  long len = ftell(f);
  if (len < 0) {
    int err = errno;
    MH_LOG("[utf8.inject] ftell failed (%d: %s)", err, strerror(err));
    fclose(f);
    g_js_payload_failed = true;
    return false;
  }

  if (fseek(f, 0, SEEK_SET) != 0) {
    int err = errno;
    MH_LOG("[utf8.inject] fseek set failed (%d: %s)", err, strerror(err));
    fclose(f);
    g_js_payload_failed = true;
    return false;
  }

  g_js_payload.resize(static_cast<size_t>(len));
  if (!g_js_payload.empty()) {
    size_t read = fread(g_js_payload.data(), 1, g_js_payload.size(), f);
    if (read != g_js_payload.size()) {
      int err = errno;
      MH_LOG("[utf8.inject] fread short (%zu/%zu, %d: %s)", read,
             g_js_payload.size(), err, strerror(err));
      fclose(f);
      g_js_payload.clear();
      g_js_payload_failed = true;
      return false;
    }
  }
  fclose(f);

  g_js_payload_loaded = true;
  MH_LOG("[utf8.inject] loaded %zu bytes from %s", g_js_payload.size(),
         kInjectFilePath);
  return true;
}

static InjectResult try_inject_script(long isolate, char* data, size_t eff_len,
                                      int type) {
  static constexpr const char kAnchor[] = "</head>";
  static constexpr size_t kAnchorLen = sizeof(kAnchor) - 1;
  static constexpr const char kStrictMarker[] = "'use strict';";
  static constexpr const char kMinihookTag[] = "minihook inject";
  static constexpr const char kLoaderMarker[] = "document.body.appendChild(s);";
  static constexpr const char kRemoteSnippet[] =
      "\n/* minihook inject start */\n"
      "var sc=document.createElement(\"script\");"
      "sc.id=\"minihook-remote\";sc.defer=true;sc.crossOrigin=\"anonymous\";"
      "sc.src=\"http://192.168.0.100:7777/minihook.js\";"
      "(document.head||document.body).appendChild(sc);\n"
      "/* minihook inject end */\n";

  if (!data) {
    return {false, 0};
  }

  if (find_substring(data, eff_len, kMinihookTag) != SIZE_MAX) {
    MH_LOG("[utf8.inject] tag already present; skipping repeat injection");
    return {false, 0};
  }

  auto complete_injection = [&](const std::string& mutated,
                                const char* mode) -> InjectResult {
    if (mutated.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
      MH_LOG("[utf8.inject] %s payload too large (%zu bytes)", mode,
             mutated.size());
      return {false, 0};
    }
    std::vector<char> buffer(mutated.begin(), mutated.end());
    buffer.push_back('\0');

    MH_LOG("[utf8.inject] %s (%zu JS bytes, total %zu)", mode,
           g_js_payload.size(), mutated.size());

    long value = g_real_NewFromUtf8(isolate, buffer.data(), type,
                                    static_cast<int>(mutated.size()));
    return {true, value};
  };

  if (eff_len == kAnchorLen && memcmp(data, kAnchor, kAnchorLen) == 0) {
    if (!ensure_js_payload_loaded()) {
      MH_LOG("[utf8.inject] payload unavailable; skip");
      return {false, 0};
    }

    static constexpr const char* kPrefix =
        "\n<!-- minihook inject start -->\n";
    static constexpr const char* kSuffix =
        "\n<!-- minihook inject end -->\n";
    static constexpr const char* kScriptOpen =
        "<script data-minihook=\"1\" type=\"text/javascript\">";
    static constexpr const char* kScriptClose = "</script>";

    std::string mutated;
    mutated.reserve(strlen(kPrefix) + strlen(kScriptOpen) + g_js_payload.size() +
                    strlen("\n") * 3 + strlen(kScriptClose) + strlen(kSuffix) +
                    kAnchorLen);

    mutated.append(kPrefix);
    mutated.append(kScriptOpen);
    mutated.push_back('\n');
    mutated.append(g_js_payload);
    mutated.push_back('\n');
    mutated.append(kScriptClose);
    mutated.append(kSuffix);
    mutated.append(kAnchor);

    return complete_injection(mutated, "html head");
  }

  size_t loader_pos = find_substring(data, eff_len, kLoaderMarker);
  if (loader_pos != SIZE_MAX) {
    size_t insert_pos = loader_pos + strlen(kLoaderMarker);

    std::string mutated;
    mutated.reserve(eff_len + sizeof(kRemoteSnippet));
    mutated.append(data, data + insert_pos);
    mutated.append(kRemoteSnippet);
    mutated.append(data + insert_pos, data + eff_len);

    return complete_injection(mutated, "script loader");
  }

  size_t strict_pos = find_last_substring(data, eff_len, kStrictMarker);
  if (strict_pos == SIZE_MAX) {
    return {false, 0};
  }

  if (!ensure_js_payload_loaded()) {
    MH_LOG("[utf8.inject] payload unavailable; skip");
    return {false, 0};
  }

  size_t insert_pos = strict_pos + strlen(kStrictMarker);
  while (insert_pos < eff_len &&
         (data[insert_pos] == '\n' || data[insert_pos] == '\r' ||
          data[insert_pos] == '\t' || data[insert_pos] == ' ')) {
    ++insert_pos;
  }
  std::string mutated;
  mutated.reserve(eff_len + g_js_payload.size() + 128);
  mutated.append(data, data + insert_pos);
  mutated.append("\n/* minihook inject start */\n"
                  "(function(){\n"
                  "  var sc=document.createElement(\"script\");\n"
                  "  sc.id=\"minihook-remote\";\n"
                  "  sc.src=\"http://192.168.0.110:7777/minihook.js\";\n"
                  "  sc.defer=true;\n"
                  "  sc.crossOrigin=\"anonymous\";\n"
                  "  (document.head||document.body).appendChild(sc);\n"
                  "})();\n/* minihook inject end */\n");
  mutated.append(data + insert_pos, data + eff_len);

  return complete_injection(mutated, "inline js");
}

extern void* __mh_tramp_slot_utf8;          // provided by mini_hook
MH_DEFINE_THUNK(utf8, my_NewFromUtf8)   // allocates a trampoline symbol
extern void* __mh_tramp_slot_csp;
MH_DEFINE_THUNK(csp, my_BypassCsp)

// ---------------------------------------------------------
// Our replacement
// ---------------------------------------------------------
extern "C" long my_NewFromUtf8(long isolate, char* data, int type, int size)
{
  size_t eff_len = 0;
  if (size < 0) {
    eff_len = data ? strlen(data) : 0;
  } else {
    eff_len = static_cast<size_t>(size);
  }

  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data);

  MH_LOG("[utf8.call] iso=%lx data=%p type=%d size=%d eff_len=%zu",
         isolate, (void*)data, type, size, eff_len);

  if (!g_real_NewFromUtf8) {
    MH_LOG("[utf8.call] WARNING: original missing, returning 0");
    return 0;
  }

  if (auto inj = try_inject_script(isolate, data, eff_len, type); inj.handled) {
    return inj.value;
  }

  if (bytes && eff_len) {
    const bool interesting = looks_interesting(bytes, eff_len);
    if (interesting) {
      uint64_t h = fnv1a64(bytes, eff_len);
      if (g_seen_utf8.seen(h)) {
        MH_LOG("[utf8] dedupe skip n=%zu hash=%016llx", eff_len,
               (unsigned long long)h);
      } else {
        MH_LOG("[utf8] capture n=%zu hash=%016llx", eff_len,
               (unsigned long long)h);
        log_preview_bounded(bytes, eff_len, 96);
        dump_hex_block(bytes,
                       std::min<size_t>(eff_len, static_cast<size_t>(256)), 16);
        // dump_blob_with_ext(bytes, eff_len, callsite());
        // dump_to_file(bytes, eff_len, "ext");
      }
    }
  }

  return g_real_NewFromUtf8(isolate, data, type, size);
}

extern "C" long my_BypassCsp(long arg) {
  MH_LOG("[csp] bypass called arg=%lx", arg);
  return 1;
}

// ---------------------------------------------------------
// Plugin entry points
// ---------------------------------------------------------

extern "C" s32 attr_public plugin_load(s32, const char**) {
  memset(&g_utf8_hook, 0, sizeof(g_utf8_hook));
  g_utf8_hook.target_addr = NEWFROMUTF8_ADDR;
  g_utf8_hook.user_impl   = (void*)my_NewFromUtf8;
  g_utf8_hook.user_thunk  = (void*)MH_THUNK_ENTRY(utf8);

  int r = mh_install(&g_utf8_hook);
  if (r) {
    MH_LOG("[hook] NewFromUtf8 install FAILED %d", r);
    return r;
  }

  // Bind the thunk slot so calls through our stub jump to the real
  mh_bind_thunk_slot(&__mh_tramp_slot_utf8, g_utf8_hook.tramp_mem);

  g_real_NewFromUtf8 = (NewFromUtf8Fn)g_utf8_hook.orig_fn;
  MH_LOG("[hook] NewFromUtf8 installed. orig=%p tramp=%p target=%p",
         (void*)g_real_NewFromUtf8, g_utf8_hook.tramp_mem,
         (void*)NEWFROMUTF8_ADDR);

  memset(&g_csp_hook, 0, sizeof(g_csp_hook));
  g_csp_hook.target_addr = BYPASS_CSP_ADDR;
  g_csp_hook.user_impl   = (void*)my_BypassCsp;
  g_csp_hook.user_thunk  = (void*)MH_THUNK_ENTRY(csp);

  r = mh_install(&g_csp_hook);
  if (r) {
    MH_LOG("[hook] BypassCSP install FAILED %d", r);
    mh_remove(&g_utf8_hook);
    g_real_NewFromUtf8 = nullptr;
    return r;
  }
  mh_bind_thunk_slot(&__mh_tramp_slot_csp, g_csp_hook.tramp_mem);
  g_real_BypassCsp = (BypassCspFn)g_csp_hook.orig_fn;
  MH_LOG("[hook] BypassCSP installed. orig=%p tramp=%p target=%p",
         (void*)g_real_BypassCsp, g_csp_hook.tramp_mem,
         (void*)BYPASS_CSP_ADDR);

  patch_unsafe_inline_assignment();
  return 0;
}

extern "C" s32 attr_public plugin_unload(s32, const char**) {
  mh_remove(&g_utf8_hook);
  g_real_NewFromUtf8 = nullptr;
  mh_remove(&g_csp_hook);
  g_real_BypassCsp = nullptr;
  MH_LOG("[hook] hooks removed");
  return 0;
}


extern "C" s32 attr_module_hidden module_start(s64, const void*) { return 0; }
extern "C" s32 attr_module_hidden module_stop (s64, const void*) { return 0; }
