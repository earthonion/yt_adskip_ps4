// Probe One - Simple single address function probe (No threads version)
// Author: earthonion

#include "plugin_common.h"
#include "Common.h"
#include <stdbool.h>
#include <orbis/libkernel.h>
// ============================================
// USER CONFIGURATION - CHANGE THIS ADDRESS
// ============================================
#define TARGET_OFFSET 0x00ab73c0   // << Address from Ghidra (with base 0x00400000)
#define TARGET_NAME "playback_control"  // << Function name
// ============================================


// Plugin metadata
attr_public const char *g_pluginName = "just print";
attr_public const char *g_pluginDesc = "probe function";
attr_public const char *g_pluginAuth = "earthonion";
attr_public u32 g_pluginVersion = 0x00000100; // 1.00

// Initialize hook


#define NO_ASLR_ADDR 0x00400000

struct proc_info procInfo;
static uint64_t call_count = 0;
static uint64_t actual_address = 0;

//function definitions
static uint32_t pattern_to_byte(const char* pattern, uint8_t* bytes);
uintptr_t PatternScan(const void* module_base, const uint64_t module_size, const char* signature, const uint64_t offset);
uint64_t get_process_size(uint64_t base_address);


// Function signature: long playback_control(long param_1, char *cmd, int param_3, int sizeof_cmd)
long (*playback_control)(long param_1, char *cmd, int param_3, int sizeof_cmd);

HOOK_INIT(playback_control);

long playback_control_hook(long param_1, char *cmd, int param_3, int sizeof_cmd) {
    final_printf("PROBE HOOK FUNCTION ENTERED");
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
    long result = 0.0;//HOOK_CONTINUE(playback_control, long(*)(long, char*, int, int), 
                               //param_1, cmd, param_3, sizeof_cmd);
    
    final_printf("  -> returned: 0x%lX\n", result);
    
    return result;
}

s32 attr_public plugin_load(s32 argc, const char* argv[]) {
    final_printf("[GoldHEN] <%s\\Ver.0x%08x> %s\n", g_pluginName, g_pluginVersion, __func__);
    
    
    if (sys_sdk_proc_info(&procInfo) != 0) {
        final_printf("[ERROR] Failed to get process info\n");
        return -1;
    }
    
    final_printf("[INFO] Process: %s\n", procInfo.name);
    final_printf("[INFO] Base Address: 0x%lX\n", procInfo.base_address);
    
    // Simple calculation: just subtract Ghidra's base and add runtime base
    uint64_t offset = TARGET_OFFSET - NO_ASLR_ADDR;
    actual_address = procInfo.base_address + offset;
    //actual_address = PatternScan(procInfo.base_address)
    
    
    uint64_t procsize = get_process_size(procInfo.base_address);
    final_printf("[INFO] Process Size: %lu\n", procsize);
    char* sig = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 80 00 00 00 89 cb 48 8b 0d d7 9e de 01 49 89 fc 85 db 48 8b 01 48 89 44 24 60 ? ? 81 fb e8 ff ff 1f";
    
    actual_address = PatternScan((const void*)procInfo.base_address, procsize, sig, 0);
    
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
    
    final_printf("[PROBE] Suspending all user threads...\n");
    scePthreadSuspendAll(); // Freeze the application

    // Install hook - use HOOK32 for 32-bit relative jumps if address is close
    // HOOK32 is safer for addresses within 2GB range
     //HOOK(playback_control);
    if (actual_address < 0x80000000) {
        final_printf("[PROBE] Using HOOK32 for low address\n");
        //HOOK32(playback_control);
    } else {
        final_printf("[PROBE] Using HOOK (64-bit) for high address\n");
        HOOK(playback_control);
    }
    
    final_printf("[PROBE] Resuming all user threads...\n");
    scePthreadResumeAll(); // Unfreeze the application

    
    final_printf("[PROBE] Hook installed successfully!\n");
    final_printf("[PROBE] Function calls will be logged\n");
    

    
    return 0;
}

s32 attr_public plugin_unload(s32 argc, const char* argv[]) {
    final_printf("[GoldHEN] %s Plugin Unloaded\n", g_pluginName);
    UNHOOK(playback_control);
    return 0;
}

s32 attr_module_hidden module_start(s64 argc, const void *args) {
    return 0;
}

s32 attr_module_hidden module_stop(s64 argc, const void *args) {
    return 0;
}


//https://github.com/Scene-Collective/ps4-hen-plugins/blob/main/common/memory.c
static uint32_t pattern_to_byte(const char* pattern, uint8_t* bytes)
{
    uint32_t count = 0;
    const char* start = pattern;
    const char* end = pattern + strlen(pattern);

    for (const char* current = start; current < end; ++current)
    {
        if (*current == '?')
        {
            ++current;
            if (*current == '?')
            {
                ++current;
            }
            bytes[count++] = -1;
        }
        else
        {
            bytes[count++] = strtoull(current, (char**)&current, 16);
        }
    }
    return count;
}

/*
 * @brief Scan for a given byte pattern on a module
 *
 * @param module_base Base of the module to search
 * @param module_size Size of the module to search
 * @param signature   IDA-style byte array pattern
 * @credit
 * https://github.com/OneshotGH/CSGOSimple-master/blob/59c1f2ec655b2fcd20a45881f66bbbc9cd0e562e/CSGOSimple/helpers/utils.cpp#L182
 * @returns           Address of the first occurrence
 */
uintptr_t PatternScan(const void* module_base, const uint64_t module_size, const char* signature, const uint64_t offset)
{
    if (!module_base || !module_size)
    {
        return 0;
    }
// constexpr uint32_t MAX_PATTERN_LENGTH = 256;
#define MAX_PATTERN_LENGTH 512
    uint8_t patternBytes[MAX_PATTERN_LENGTH] = {0};
    int32_t patternLength = pattern_to_byte(signature, patternBytes);
    if (!patternLength || patternLength >= MAX_PATTERN_LENGTH)
    {
        return 0;
    }
    uint8_t* scanBytes = (uint8_t*)module_base;

    for (uint64_t i = 0; i < module_size; ++i)
    {
        bool found = true;
        for (int32_t j = 0; j < patternLength; ++j)
        {
            if (scanBytes[i + j] != patternBytes[j] &&
                patternBytes[j] != 0xff)
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (((uintptr_t)&scanBytes[i] + offset));
        }
    }
    return 0;
}


uint64_t get_process_size(uint64_t base_address) {
    uint64_t current_address = base_address;
    uint64_t total_size = 0;
    OrbisKernelVirtualQueryInfo info;


    for (int i = 0; i < 100; ++i) { // Safety break: limit to 100 segments
        int result = sceKernelVirtualQuery(
            (void*)current_address,
            0,
            &info,
            sizeof(info)
        );

        if (result != 0) {
            break;
        }

        // --- Refined Heuristics using real struct fields ---

        // 1. Check for memory gaps. If the start of the returned segment doesn't match where
        //    we are currently scanning, it means we've crossed an unmapped gap.
        if (info.start_addr != (void*)current_address) {
            final_printf("[VQuery] Detected memory gap at 0x%lX. Stopping iteration.\n", current_address);
            break;
        }

        // 2. Check if this segment is stack memory. We don't want to scan the stack.
        if (info.isStack) {
            final_printf("[VQuery] Reached stack segment. Stopping iteration.\n");
            break;
        }
        
        // 3. Optional: Check segment name. All segments for "eboot.bin" might have a consistent name.
        //    If info.name changes from the initial segment's name, you could stop.
        //    Example: final_printf("[VQuery] Segment Name: %s\n", info.name);

        // --- Calculate size and advance ---
        uint64_t segment_size = (uint64_t)info.end_addr - (uint64_t)info.start_addr;
        total_size += segment_size;
        current_address = (uint64_t)info.end_addr;
    }

    final_printf("[VQuery] Total scannable size calculated: %lu bytes (%lu MB)\n",
                 total_size, total_size / 1024 / 1024);
    return total_size;
}
