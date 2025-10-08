// Simple examples showing how to use the mini_hook library
#include "mini_hook.h"
#include <stdio.h>
#include <time.h>

// Example 1: Basic function hook with statistics
typedef int (*example_func_t)(int a, int b);
example_func_t original_example_func;
mh_hook_t g_example_hook = {0};
mh_stats_t* g_example_stats = NULL;

extern "C" int example_callback(int a, int b) {
    // Update statistics
    if (g_example_stats) {
        g_example_stats->call_count++;
        g_example_stats->last_call_time = time(NULL);
    }
    
    mh_log("[HOOK] example_func called with a=%d, b=%d\n", a, b);
    
    // You can modify arguments here if needed
    if (a < 0) a = 0;  // Prevent negative values
    
    // Call original (if we're in thunk mode, this happens automatically)
    return 0;
}

MH_DEFINE_THUNK(example, example_callback)
extern void *__mh_tramp_slot_example;

void setup_example_hook(uint64_t target_addr) {
    // Setup hook structure
    g_example_hook.target_addr = target_addr;
    g_example_hook.user_impl = (void*)example_callback;
    g_example_hook.user_thunk = (void*)MH_THUNK_ENTRY(example);
    
    // Install the hook
    int result = mh_install(&g_example_hook);
    if (result == 0) {
        mh_log("[INFO] Hook installed successfully\n");
        
        // Bind thunk slot
        mh_bind_thunk_slot(&__mh_tramp_slot_example, g_example_hook.tramp_mem);
        
        // Get stats object
        g_example_stats = mh_get_stats(&g_example_hook);
        
        // Cast original function
        original_example_func = (example_func_t)g_example_hook.orig_fn;
    } else {
        mh_log("[ERROR] Failed to install hook: %d\n", result);
    }
}

// Example 2: Toggle hook on/off
void toggle_example_hook() {
    static bool enabled = true;
    
    enabled = !enabled;
    int result = mh_enable(&g_example_hook, enabled);
    
    if (result == 0) {
        mh_log("[INFO] Hook %s\n", enabled ? "enabled" : "disabled");
    }
}

// Example 3: Dump hook information
void dump_hook_info() {
    if (!mh_is_installed(&g_example_hook)) {
        mh_log("[INFO] Hook not installed\n");
        return;
    }
    
    mh_log("[INFO] Hook Information:\n");
    mh_log("  Target: 0x%lX\n", g_example_hook.target_addr);
    mh_log("  Trampoline: %p\n", g_example_hook.tramp_mem);
    mh_log("  Stolen bytes: %zu\n", g_example_hook.stolen_len);
    mh_log("  Mode: %s\n", g_example_hook.mode == MH_MODE_THUNK ? "THUNK" : "WRAPPER");
    
    // Dump original bytes
    mh_hexdump(g_example_hook.original, g_example_hook.stolen_len, "Original bytes");
    
    // Show statistics
    if (g_example_stats) {
        mh_log("  Statistics:\n");
        mh_log("    Calls: %llu\n", g_example_stats->call_count);
        mh_log("    Last call: %llu\n", g_example_stats->last_call_time);
    }
}

// Example 4: Multiple hooks with priority (manual chain)
typedef struct {
    mh_hook_t hook;
    const char* name;
    int priority;
} prioritized_hook_t;

prioritized_hook_t g_hook_chain[3] = {
    { {0}, "Logger", 1 },
    { {0}, "Validator", 2 },
    { {0}, "Modifier", 3 }
};

// Example 5: Pattern scanning to find function
uint64_t find_function_by_pattern() {
    // Example pattern for a common function prologue
    // push rbp; mov rbp, rsp; sub rsp, XX
    uint8_t pattern[] = {
        0x55,             // push rbp
        0x48, 0x89, 0xE5, // mov rbp, rsp
        0x48, 0x83, 0xEC  // sub rsp, ... (incomplete, last byte varies)
    };
    
    uint64_t module_base = 0x400000;  // Example base
    size_t search_size = 0x100000;    // Search 1MB
    
    uint8_t* search_ptr = (uint8_t*)module_base;
    for (size_t i = 0; i < search_size - sizeof(pattern); i++) {
        bool match = true;
        for (size_t j = 0; j < sizeof(pattern); j++) {
            if (search_ptr[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            mh_log("[SCAN] Found pattern at 0x%lX\n", module_base + i);
            return module_base + i;
        }
    }
    
    return 0;
}

// Example 6: Safe hook with error handling
int safe_install_hook(mh_hook_t* hook, uint64_t target, void* impl, void* thunk) {
    if (!hook || !target || !impl) {
        mh_log("[ERROR] Invalid parameters\n");
        return -1;
    }
    
    // Check if already installed
    if (hook->installed) {
        mh_log("[WARN] Hook already installed, removing first\n");
        mh_remove(hook);
    }
    
    // Setup hook
    memset(hook, 0, sizeof(mh_hook_t));
    hook->target_addr = target;
    hook->user_impl = impl;
    hook->user_thunk = thunk;
    
    // Verify target is readable
    uint8_t test_read[16];
    if (memcpy(test_read, (void*)target, sizeof(test_read)) == NULL) {
        mh_log("[ERROR] Target address not readable\n");
        return -2;
    }
    
    // Install with retry
    int attempts = 3;
    int result = -1;
    
    while (attempts-- > 0) {
        result = mh_install(hook);
        if (result == 0) {
            mh_log("[SUCCESS] Hook installed on attempt %d\n", 3 - attempts);
            break;
        }
        mh_log("[RETRY] Installation failed, retrying...\n");
    }
    
    return result;
}

// Example 7: Cleanup function
void cleanup_all_hooks() {
    mh_log("[CLEANUP] Removing all hooks...\n");
    
    // Remove example hook
    if (g_example_hook.installed) {
        mh_remove(&g_example_hook);
        mh_log("  - Removed example hook\n");
    }
    
    // Remove chain hooks
    for (int i = 0; i < 3; i++) {
        if (g_hook_chain[i].hook.installed) {
            mh_remove(&g_hook_chain[i].hook);
            mh_log("  - Removed %s hook\n", g_hook_chain[i].name);
        }
    }
    
    mh_log("[CLEANUP] Complete\n");
}