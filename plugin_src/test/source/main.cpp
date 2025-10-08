//==============================================================================
// Simplified Hook Plugin
// Author: earthonion
// Built upon the successful techniques from the GoldHEN Game Patcher.
//==============================================================================

//==============================================================================
// Includes
//==============================================================================
#include "plugin_common.h"
#include "utils.h"
//#include "patch.h"
#include "mini_hook.h"
#include <orbis/libkernel.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "hde/hde64.h"
#include <stdbool.h>
#include <ctype.h>

//==============================================================================
// Configuration
//==============================================================================
// This is the stable, ASLR-proof offset you found with the pattern scanner.
// (0xAB73C4 - 0x400000 = 0x6B73C4)
#define TARGET_OFFSET 0x6B73C4
#define TARGET_NAME "playback_control"

//==============================================================================
// Plugin Metadata
//==============================================================================
attr_public const char *g_pluginName = "Simplified_Hooker";
attr_public const char *g_pluginDesc = "A stable, manual hook using game patcher techniques.";
attr_public const char *g_pluginAuth = "earthonion";
attr_public u32 g_pluginVersion = 0x00000600; // Version 6.0


typedef long (*playback_t)(long p1, char *cmd, int p3, int sizeof_cmd);
static void dump_cmd(const void* buf, int len);
extern "C" bool is_timestamp(const char *s);


// ---- mini YouTube ID parser for raw buffers ---------------------------------


extern "C" long pb_callback(long p1, char *cmd, int p3, int sz) {
    mh_log("[HOOK] playback p1=0x%lX cmd=%p p3=%d sz=%d\n", p1, cmd, p3, sz);
    dump_cmd(cmd, sz);
    //mh_log(buf);
    return 0; // we still tail-jump to the original via trampoline
}

// 2) Your C callback (called inside the thunk, before the original)
//extern "C" long pb_callback(long p1, char *cmd, int p3, int sz) {
//    mh_log("[HOOK] playback p1=0x%lX cmd=%p p3=%d sz=%d\n", p1, cmd, p3, sz);
    // You can modify args here if you want by writing to memory pointed by cmd, etc.
//    dump_cmd(cmd, sz);
//    return 0; // return value here is ignored; we tail-jump to original via trampoline
//}

// 3) Hook object + thunk + slot
static mh_hook_t g_pb_hook = {0};
MH_DEFINE_THUNK(pb, pb_callback)  // emits __mh_tramp_slot_pb and thunk symbol

extern void *__mh_tramp_slot_pb;


//==============================================================================
// Logging
//==============================================================================
void log_info(const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    sceKernelDebugOutText(0, buffer);
}


//==============================================================================
// Hook Handler Function
//==============================================================================




extern "C" {



s32 attr_public plugin_load(s32 argc, const char* argv[]) {
    // fetch eboot base
    uint64_t module_base = 0;
    uint32_t module_size = 0;
    OrbisKernelModuleInfo mi; mi.size = sizeof(mi);
    if (!get_module_info(mi, "eboot.bin", &module_base, &module_size)) {
        mh_log("[hook] get_module_info failed\n");
        return -1;
    }

    memset(&g_pb_hook, 0, sizeof(g_pb_hook));
    g_pb_hook.target_addr = module_base + TARGET_OFFSET; // 0x6B73C4
    g_pb_hook.user_impl   = (void*)pb_callback;
    g_pb_hook.user_thunk  = (void*)MH_THUNK_ENTRY(pb);

    int r = mh_install(&g_pb_hook);
    if (r) { mh_log("[hook] install failed %d\n", r); return r; }

    // Bind the thunk’s slot to the trampoline so `jmp *slot(%rip)` knows where to go
    mh_bind_thunk_slot(&__mh_tramp_slot_pb, g_pb_hook.tramp_mem);

    // Optional: keep a typed pointer to the original
    playback_t original = (playback_t)g_pb_hook.orig_fn;
    (void)original;

    mh_log("[hook] playback installed. thunk=%p tramp=%p\n",
           g_pb_hook.user_thunk, g_pb_hook.tramp_mem);
    return 0;
}



s32 attr_public plugin_unload(s32 argc, const char* argv[]) {
    log_info("[Plugin] Unloading...\n");

    mh_remove(&g_pb_hook);

    log_info("[Plugin] Unloaded.\n");
    return 0;
}

s32 attr_module_hidden module_start(s64 argc, const void *args)
{
    return 0;
}

s32 attr_module_hidden module_stop(s64 argc, const void *args)
{
    return 0;
}

bool is_timestamp(const char *s) {
    // must be 4 or 5 chars: "m:ss" or "mm:ss"
    int len = 0;
    while (s[len]) len++;
    if (len < 4 || len > 5) return false;

    // split at colon
    const char *colon = s;
    while (*colon && *colon != ':') colon++;
    if (!*colon) return false; // no colon

    // minutes part
    for (const char *p = s; p < colon; p++) {
        if (!isdigit(*p)) return false;
    }

    // seconds part (must be exactly 2 digits)
    if (colon[1] && colon[2] && !colon[3]) {
        if (isdigit(colon[1]) && isdigit(colon[2])) {
            int sec = (colon[1] - '0') * 10 + (colon[2] - '0');
            return sec < 60;
        }
    }
    return false;
}


static void dump_cmd(const void* buf, int len) {
    if (!buf || len <= 0) { 
        mh_log("  [cmd] <null/empty>\n"); 
        return; 
    }
    
    const unsigned char* p = (const unsigned char*)buf;
    
    // For HTTP requests, we might need to handle much larger buffers
    // Typical HTTP request headers can be 4-8KB, some servers allow up to 16KB
    const int max_display_len = 1196187; // 8KB should cover most HTTP requests
    int display_len = len < max_display_len ? len : max_display_len;
    
    // Allocate buffer dynamically to handle larger requests
    char* ascii = (char*)malloc(display_len + 1);
    if (!ascii) {
        mh_log("  [cmd] <memory allocation failed>\n");
        return;
    }
    
    // ASCII preview (printable only)
    for (int i = 0; i < display_len; ++i) {
        unsigned char c = p[i];
        ascii[i] = (c >= 32 && c < 1196187
) ? (char)c : '.';
    }
    ascii[display_len] = 0;
    
    // Log with truncation indicator if needed
    if (len > max_display_len) {
        mh_log("  [cmd ascii] %s... [truncated %d/%d bytes]\n", ascii, display_len, len);
    } else {
        mh_log("  [cmd ascii] %s\n", ascii);
    }
    
    free(ascii);
}

}


