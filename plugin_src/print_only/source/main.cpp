//==============================================================================
// Includes
//==============================================================================
#include "plugin_common.h" // Your base SDK header
#include <orbis/libkernel.h> // For sceKernel* functions
#include <minhook.h>       // MinHook library header
#include <stdbool.h>       // For true/false
#include <stdarg.h> // Required for va_list
#include <stdio.h>  // Required for vsnprintf




pthread_t start_thread;
pthread_t stop_thread;
uintptr_t actual_address = 0;

//==============================================================================
// Plugin Metadata
//==============================================================================
attr_public const char *g_pluginName = "playback_control_hooker";
attr_public const char *g_pluginDesc = "Hooking playback_control using MinHook.";
attr_public const char *g_pluginAuth = "earthonion";
attr_public u32 g_pluginVersion = 0x00000200; // Version 2.0

//==============================================================================
// Function Declarations (for pattern scan and size calculation)
//==============================================================================
void log_info(const char* format, ...);
static uint32_t pattern_to_byte(const char* pattern, uint8_t* bytes);
uintptr_t PatternScan(uintptr_t module_base, const uint64_t module_size, const char* signature);//, const uint64_t offset);
uint64_t get_process_size(uint64_t base_address);

//==============================================================================
// Hook Target Definition: playback_control
//==============================================================================

// 1. Define the function signature type for readability.
typedef long (*playback_control_t)(long param_1, char *cmd, int param_3, int sizeof_cmd);

// 2. Create a pointer to hold the address of the original function (trampoline).
// MinHook will populate this pointer for us.
playback_control_t playback_control_original = nullptr;


//==============================================================================
// Hook Handler Function
//==============================================================================
long playback_control_hook(long param_1, char *cmd, int param_3, int sizeof_cmd) {
    static uint64_t call_count = 0;
    call_count++;
    log_info("[PROBE] playback_control called (call #%lu)\n", call_count);
    log_info("  param_1: 0x%lX\n", param_1);
    log_info("  cmd: %p", cmd);
    if (cmd && sizeof_cmd > 0) {
        log_info(" -> \"%.50s\"", cmd);
    }
    log_info("\n");
    log_info("  param_3: %d (0x%X)\n", param_3, param_3);
    log_info("  sizeof_cmd: %d\n", sizeof_cmd);

    long result = playback_control_original(param_1, cmd, param_3, sizeof_cmd);

    log_info("  -> returned: 0x%lX\n", result);

    return result;
}




//==============================================================================
// Initialization and Shutdown Logic (Threaded)
//==============================================================================

/**
 * @brief Thread function to install all hooks.
 */
void *main_start(void *arg) {
    log_info( "[MinHook Port] Starting hook installation thread...\n");
    
    log_info( "[MinHook Port] Signature found at address: 0x%lX\n", actual_address);
    log_info("[MinHook Port] INITIALIZING HOOK....");
    // --- 3. Initialize MinHook ---
    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        log_info( "[MinHook Port] ERROR: MH_Initialize failed: %d\n", status);
        pthread_exit(nullptr);
        return nullptr;
    }

    // --- 1. Find Process Info ---
    struct proc_info procInfo;
    if (sys_sdk_proc_info(&procInfo) != 0) {
        log_info( "[MinHook Port] ERROR: Failed to get process info.\n");
        pthread_exit(nullptr);
        return nullptr;
    }
    log_info( "[MinHook Port] Process: %s, Base Address: 0x%lX\n", procInfo.name, procInfo.base_address);

    // --- 2. Find Function Address via Pattern Scan ---
    //uint64_t procsize = get_process_size(procInfo.base_address);
    //if (procsize == 0) {
    //    log_info( "[MinHook Port] ERROR: Failed to calculate process size.\n");
    //    pthread_exit(nullptr);
    //    return nullptr;
    //}
    
    uint64_t procsize = 500 * 1024 * 1024; // 500 MB
    log_info("[MinHook Port] Using fixed scan size of %lu MB\n", procsize / (1024*1024));
    // =============================================
    
    
    const char* sig = "55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 e4 e0 48 81 ec 80 00 00 00 89 cb 48 8b 0d d7 9e de 01 49 89 fc 85 db 48 8b 01 48 89 44 24 60 ? ? 81 fb e8 ff ff 1f";
    actual_address = 0x00AB73C4;//PatternScan(procInfo.base_address, procsize, sig);// offset = 4 to load hook after func prologue
    
    if (actual_address == 0) {
        log_info( "[MinHook Port] ERROR: Pattern scan failed to find signature.\n");
        pthread_exit(nullptr);
        return nullptr;
    }

    log_info("[MinHook Port] CREATING HOOK....");
    // --- 4. Create the Hook ---
    
    status = MH_CreateHook((LPVOID)actual_address, (LPVOID)playback_control_hook, (LPVOID*)&playback_control_original);
    //log_info("");
    
    if (status != MH_OK) {
        log_info( "[MinHook Port] ERROR: MH_CreateHook failed: %d\n", status);
        MH_Uninitialize(); // clean up initialization on failure
        pthread_exit(nullptr);
        return nullptr;
    }

    // --- 5. Enable the Hook ---
    log_info("[MinHook Port] ENABLINGING HOOK....");
    scePthreadSuspendAll();
    status = MH_EnableHook((LPVOID)actual_address);
    scePthreadResumeAll();
    if (status != MH_OK) {
        log_info( "[MinHook Port] ERROR: MH_EnableHook failed: %d\n", status);
        MH_Uninitialize(); // clean up initialization on failure
        pthread_exit(nullptr);
        return nullptr;
    }

    log_info( "[MinHook Port] Hook installed successfully!\n");
    pthread_exit(nullptr);
    return nullptr;
}

/**
 * @brief Thread function to remove all hooks and clean up.
 */
void *main_stop(void *arg) {
    log_info( "[MinHook Port] Removing hooks...\n");

    if (actual_address != 0) {
        scePthreadSuspendAll();
        MH_DisableHook((LPVOID)actual_address);
        scePthreadResumeAll();
    }
    MH_Uninitialize();
    
    log_info( "[MinHook Port] Hooks removed.\n");
    pthread_exit(nullptr);
    return nullptr;
}

//==============================================================================
// Initialization and Shutdown Logic
//==============================================================================





void init() {
    log_info( "[MinHook Port] init() called.\n");
    pthread_create(&start_thread, nullptr, main_start, nullptr);
    pthread_join(start_thread, nullptr); // Wait for the init thread to finish
}

/**
 * @brief Starts the cleanup thread and releases resources.
 */
void fini() {
    log_info( "[MinHook Port] fini() called.\n");
    pthread_create(&stop_thread, nullptr, main_stop, nullptr);
    pthread_join(stop_thread, nullptr); // Wait for the cleanup thread to finish
}

//==============================================================================
// Plugin Entry Points
//==============================================================================

s32 attr_public plugin_load(s32 argc, const char* argv[]) {
    init(); // Call shared initialization logic
    return 0;
}

s32 attr_public plugin_unload(s32 argc, const char* argv[]) {
    fini(); // Call shared cleanup logic
    return 0;
}

extern "C" {
s32 attr_module_hidden module_start(s64 argc, const void *args) {
    init(); // Call shared initialization logic
    return 0;
}

s32 attr_module_hidden module_stop(s64 argc, const void *args) {
    fini(); // Call shared cleanup logic
    return 0;
}
}


//==============================================================================
// Helper Function Implementations (Pasted from your previous code)
//==============================================================================

// ... [You must paste your implementations for get_process_size, PatternScan, and pattern_to_byte here] ...

// Example placeholder for get_process_size if you need to re-paste it:

static uint32_t pattern_to_byte(const char* pattern, uint8_t* bytes, uint32_t max_size)
{
    uint32_t count = 0;
    const char* start = pattern;
    const char* end = pattern + strlen(pattern);

    for (const char* current = start; current < end; ++current)
    {
        
        if (count >= max_size){
            log_info("[PATTERNSCAN] WARNING: Signature toolong. Truncating"); 
            break;
        
        }
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
//==============================================================================
// New, Safe Pattern Scanning Logic
//==============================================================================

/**
 * @brief Safely scans for a byte pattern by iterating through valid memory segments.
 * This avoids reading from unmapped memory, which can cause heap corruption.
 *
 * @param module_base Base address to start the scan from.
 * @param scan_size   The total range of memory to scan across.
 * @param signature   IDA-style byte array pattern.
 * @return Address of the first occurrence, or 0 if not found.
 */
uintptr_t PatternScan(uintptr_t module_base, size_t scan_size, const char* signature)
{
    // --- 1. Parse the signature into bytes ---
    #define MAX_PATTERN_LENGTH 512
    uint8_t patternBytes[MAX_PATTERN_LENGTH] = {0};
    uint32_t patternLength = pattern_to_byte(signature, patternBytes, MAX_PATTERN_LENGTH);
    if (!patternLength) return 0;

    // --- 2. Iterate through memory segments ---
    uintptr_t scan_current = module_base;
    uintptr_t scan_end = module_base + scan_size;

    OrbisKernelVirtualQueryInfo info;

    while (scan_current < scan_end)
    {
        // Query the memory segment at the current address
        if (sceKernelVirtualQuery((void*)scan_current, 0, &info, sizeof(info)) != 0)
        {
            // If query fails, we can't continue, so stop.
            return 0;
        }

        // We are only interested in committed, readable memory
        if (info.isCommitted && (info.prot & PROT_READ))
        {
            uintptr_t block_start = (uintptr_t)info.start_addr;
            uintptr_t block_end = (uintptr_t)info.end_addr;
            
            // --- 3. Scan within the valid memory block ---
            for (uintptr_t i = block_start; i < block_end - patternLength; ++i)
            {
                bool found = true;
                for (uint32_t j = 0; j < patternLength; ++j)
                {
                    if (patternBytes[j] != 0xFF && ((uint8_t*)i)[j] != patternBytes[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    // Signature found! Return the address.
                    return i;
                }
            }
        }

        // Move to the start of the next memory segment
        if ((uintptr_t)info.end_addr <= scan_current)
        {
            // Failsafe to prevent infinite loops on error
            break;
        }
        scan_current = (uintptr_t)info.end_addr;
    }

    return 0; // Not found
}
uint64_t get_process_size(uint64_t base_address) {
    uint64_t current_address = base_address;
    uint64_t total_size = 0;
    OrbisKernelVirtualQueryInfo info; // Make sure this struct definition is available

    for (int i = 0; i < 100; ++i) { 
        int result = sceKernelVirtualQuery((void*)current_address, 0, &info, sizeof(info));
        if (result != 0 || info.start_addr != (void*)current_address) {
            break;
        }
        if (info.isStack) {
            break;
        }
        uint64_t segment_size = (uint64_t)info.end_addr - (uint64_t)info.start_addr;
        total_size += segment_size;
        current_address = (uint64_t)info.end_addr;
    }
    return total_size;
}


/**
 * @brief Formats a string and prints it to the kernel debug output.
 * * @param format The format string, like printf.
 * @param ...    The variable arguments for the format string.
 */
void log_info(const char* format, ...)
{
    char buffer[1024]; // A 1KB buffer for the log message.
    va_list args;

    // Format the string with the variable arguments
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Print the fully formatted string to the debug output
    sceKernelDebugOutText(0,buffer);
}
