// Probe One - Simple single address function probe (No threads version)
// Author: earthonion

#include "plugin_common.h"
#include "Common.h"

// ============================================
// USER CONFIGURATION - CHANGE THIS ADDRESS
// ============================================
#define TARGET_OFFSET 0x00ab73c0   // << Address from Ghidra (with base 0x00400000)
#define TARGET_NAME "playback_control"  // << Function name
// ============================================



// Plugin metadata
attr_public const char *g_pluginName = "probe_one";
attr_public const char *g_pluginDesc = "probe function";
attr_public const char *g_pluginAuth = "earthonion";
attr_public u32 g_pluginVersion = 0x00000100; // 1.00

#define NO_ASLR_ADDR 0x00400000

struct proc_info procInfo;
static uint64_t call_count = 0;
static uint64_t actual_address = 0;

// Function signature: long playback_control(long param_1, char *cmd, int param_3, int sizeof_cmd)
long (*playback_control)(long param_1, char *cmd, int param_3, int sizeof_cmd);

// Initialize hook
HOOK_INIT(playback_control);

// Hook handler with proper parameters
long playback_control_hook(long param_1, char *cmd, int param_3, int sizeof_cmd) {
    call_count++;
    
    // Log the function call with parameters
    final_printf("[PROBE] %s called (call #%lu)\n", TARGET_NAME, call_count);
    final_printf("  param_1: 0x%lX\n", param_1);
    final_printf("  cmd: %p", cmd);
    if (cmd && sizeof_cmd > 0) {
        final_printf(" -> \"%.50s\"", cmd);  // Show first 50 chars of command
    }
    final_printf("\n");
    final_printf("  param_3: %d (0x%X)\n", param_3, param_3);
    final_printf("  sizeof_cmd: %d\n", sizeof_cmd);
    
    // Call original function
    long result = HOOK_CONTINUE(playback_control, long(*)(long, char*, int, int), 
                               param_1, cmd, param_3, sizeof_cmd);
    
    final_printf("  -> returned: 0x%lX\n", result);
    
    return result;
}

s32 attr_public plugin_load(s32 argc, const char* argv[]) {
    final_printf("[GoldHEN] <%s\\Ver.0x%08x> %s\n", g_pluginName, g_pluginVersion, __func__);
    final_printf("[GoldHEN] Plugin Author(s): %s\n", g_pluginAuth);
    
    // Get process information
    if (sys_sdk_proc_info(&procInfo) != 0) {
        final_printf("[ERROR] Failed to get process info\n");
        return -1;
    }
    
    final_printf("[INFO] Process: %s\n", procInfo.name);
    final_printf("[INFO] Base Address: 0x%lX\n", procInfo.base_address);
    
    // Simple calculation: just subtract Ghidra's base and add runtime base
    uint64_t offset = TARGET_OFFSET - NO_ASLR_ADDR;
    actual_address = procInfo.base_address + offset;
    
    final_printf("[PROBE] Offset from base: 0x%lX\n", offset);
    final_printf("[PROBE] Runtime address: 0x%lX (base + 0x%lX)\n", actual_address, offset);
    
    // Safety check
    if (actual_address < 0x10000 || actual_address > 0x800000000000) {
        final_printf("[ERROR] Invalid address 0x%lX - aborting hook!\n", actual_address);
        return -1;
    }
    
    final_printf("[PROBE] Hooking %s at 0x%lX\n", TARGET_NAME, actual_address);
    
    // Set function pointer
    playback_control = (long(*)(long, char*, int, int))actual_address;
    
    // Install hook - use HOOK32 for 32-bit relative jumps if address is close
    // HOOK32 is safer for addresses within 2GB range
    if (actual_address < 0x80000000) {
        final_printf("[PROBE] Using HOOK32 for low address\n");
        HOOK32(playback_control);
    } else {
        final_printf("[PROBE] Using HOOK (64-bit) for high address\n");
        HOOK(playback_control);
    }
    
    final_printf("[PROBE] Hook installed successfully!\n");
    final_printf("[PROBE] Function calls will be logged\n");
    
    return 0;
}

s32 attr_public plugin_unload(s32 argc, const char* argv[]) {
    final_printf("[GoldHEN] <%s\\Ver.0x%08x> %s\n", g_pluginName, g_pluginVersion, __func__);
    
    // Print final statistics
    final_printf("[STATS] %s was called %lu times\n", TARGET_NAME, call_count);
    
    // Unhook
    UNHOOK(playback_control);
    
    final_printf("[GoldHEN] %s Plugin Unloaded\n", g_pluginName);
    return 0;
}

s32 attr_module_hidden module_start(s64 argc, const void *args) {
    return 0;
}

s32 attr_module_hidden module_stop(s64 argc, const void *args) {
    return 0;
}
