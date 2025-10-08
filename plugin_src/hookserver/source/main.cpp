//==============================================================================
// Hook Server Plugin
// Author: earthonion
// A server that accepts commands to dynamically set hooks and log parameters
//==============================================================================

//==============================================================================
// Includes
//==============================================================================
#include "plugin_common.h"
#include "utils.h"
#include "mini_hook.h"
#include <orbis/libkernel.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "hde/hde64.h"
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

//==============================================================================
// Configuration
//==============================================================================
#define SERVER_PORT 9026
#define MAX_HOOKS 32
#define MAX_CMD_SIZE 256

//==============================================================================
// Plugin Metadata
//==============================================================================
attr_public const char *g_pluginName = "Hook_Server";
attr_public const char *g_pluginDesc = "TCP server for dynamic hooking and parameter logging";
attr_public const char *g_pluginAuth = "earthonion";
attr_public u32 g_pluginVersion = 0x00000700; // Version 7.0

//==============================================================================
// Hook Management Structures
//==============================================================================
struct HookEntry {
    mh_hook_t hook;
    uint64_t address;
    bool active;
    char name[64];
    void* thunk;
    void* callback;
};

static HookEntry g_hooks[MAX_HOOKS] = {0};
static int g_hook_count = 0;
static pthread_mutex_t g_hook_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_server_sockfd = -1;
static pthread_t g_server_thread;
static bool g_server_running = false;
static uint64_t g_module_base = 0;
static uint32_t g_module_size = 0;

//==============================================================================
// Generic Hook Callback
//==============================================================================
extern "C" void generic_hook_callback(uint64_t rdi, uint64_t rsi, uint64_t rdx, 
                                     uint64_t rcx, uint64_t r8, uint64_t r9) {
    // Find which hook this came from based on return address
    void* ret_addr = __builtin_return_address(0);
    
    pthread_mutex_lock(&g_hook_mutex);
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].active) {
            // Log the parameters
            char log_msg[512];
            snprintf(log_msg, sizeof(log_msg), 
                "[HOOK:%s @ 0x%lX] rdi=0x%lX rsi=0x%lX rdx=0x%lX rcx=0x%lX r8=0x%lX r9=0x%lX\n",
                g_hooks[i].name, g_hooks[i].address,
                rdi, rsi, rdx, rcx, r8, r9);
            mh_log(log_msg);
            
            // Send to connected clients if any
            // (We'll implement this later)
            break;
        }
    }
    pthread_mutex_unlock(&g_hook_mutex);
}

// Define generic thunks for multiple hooks
// Declare slots as extern first
extern "C" {
    void* __mh_tramp_slot_generic_0 = 0;
    void* __mh_tramp_slot_generic_1 = 0;
    void* __mh_tramp_slot_generic_2 = 0;
    void* __mh_tramp_slot_generic_3 = 0;
    void* __mh_tramp_slot_generic_4 = 0;
    void* __mh_tramp_slot_generic_5 = 0;
    void* __mh_tramp_slot_generic_6 = 0;
    void* __mh_tramp_slot_generic_7 = 0;
}

#define DEFINE_GENERIC_THUNK(n) \
    extern "C" __attribute__((naked)) void __mh_thunk_generic_##n(void) { \
        __asm__ volatile( \
            "push %rbp\n" \
            "mov  %rsp, %rbp\n" \
            "sub  $0x60, %rsp\n" \
            "mov  %rdi, -0x08(%rbp)\n" \
            "mov  %rsi, -0x10(%rbp)\n" \
            "mov  %rdx, -0x18(%rbp)\n" \
            "mov  %rcx, -0x20(%rbp)\n" \
            "mov  %r8,  -0x28(%rbp)\n" \
            "mov  %r9,  -0x30(%rbp)\n" \
            "mov  %r10, -0x38(%rbp)\n" \
            "mov  %r11, -0x40(%rbp)\n" \
            "call generic_hook_callback\n" \
            "mov  -0x08(%rbp), %rdi\n" \
            "mov  -0x10(%rbp), %rsi\n" \
            "mov  -0x18(%rbp), %rdx\n" \
            "mov  -0x20(%rbp), %rcx\n" \
            "mov  -0x28(%rbp), %r8\n" \
            "mov  -0x30(%rbp), %r9\n" \
            "mov  -0x38(%rbp), %r10\n" \
            "mov  -0x40(%rbp), %r11\n" \
            "leave\n" \
            "lea __mh_tramp_slot_generic_" #n "(%rip), %rax\n" \
            "jmp *(%rax)\n" \
        ); \
    }

// Create 8 generic thunks for now
DEFINE_GENERIC_THUNK(0)
DEFINE_GENERIC_THUNK(1)
DEFINE_GENERIC_THUNK(2)
DEFINE_GENERIC_THUNK(3)
DEFINE_GENERIC_THUNK(4)
DEFINE_GENERIC_THUNK(5)
DEFINE_GENERIC_THUNK(6)
DEFINE_GENERIC_THUNK(7)

// Array of thunk functions and slots
static struct {
    void* thunk;
    void** slot;
} g_thunk_table[] = {
    { (void*)__mh_thunk_generic_0, (void**)&__mh_tramp_slot_generic_0 },
    { (void*)__mh_thunk_generic_1, (void**)&__mh_tramp_slot_generic_1 },
    { (void*)__mh_thunk_generic_2, (void**)&__mh_tramp_slot_generic_2 },
    { (void*)__mh_thunk_generic_3, (void**)&__mh_tramp_slot_generic_3 },
    { (void*)__mh_thunk_generic_4, (void**)&__mh_tramp_slot_generic_4 },
    { (void*)__mh_thunk_generic_5, (void**)&__mh_tramp_slot_generic_5 },
    { (void*)__mh_thunk_generic_6, (void**)&__mh_tramp_slot_generic_6 },
    { (void*)__mh_thunk_generic_7, (void**)&__mh_tramp_slot_generic_7 },
};

//==============================================================================
// Command Processing
//==============================================================================
void send_response(int client_fd, const char* response) {
    write(client_fd, response, strlen(response));
}

void process_hook_command(int client_fd, const char* cmd) {
    char response[512];
    
    // Parse command: "hook log 0xADDRESS [name]"
    if (strncmp(cmd, "hook log ", 9) == 0) {
        const char* addr_str = cmd + 9;
        uint64_t addr = 0;
        char name[64] = "unnamed";
        
        // Parse address
        if (sscanf(addr_str, "0x%lx", &addr) != 1) {
            snprintf(response, sizeof(response), "ERROR: Invalid address format\n");
            send_response(client_fd, response);
            return;
        }
        
        // Optional name after address
        const char* name_start = strchr(addr_str, ' ');
        if (name_start) {
            strncpy(name, name_start + 1, sizeof(name) - 1);
            // Remove newline if present
            char* newline = strchr(name, '\n');
            if (newline) *newline = '\0';
        }
        
        pthread_mutex_lock(&g_hook_mutex);
        
        // Check if we have available hooks
        if (g_hook_count >= 8) { // Limited by our thunk count
            snprintf(response, sizeof(response), "ERROR: Maximum hooks reached\n");
            pthread_mutex_unlock(&g_hook_mutex);
            send_response(client_fd, response);
            return;
        }
        
        // Check if address is already hooked
        for (int i = 0; i < g_hook_count; i++) {
            if (g_hooks[i].address == addr && g_hooks[i].active) {
                snprintf(response, sizeof(response), "ERROR: Address 0x%lX already hooked\n", addr);
                pthread_mutex_unlock(&g_hook_mutex);
                send_response(client_fd, response);
                return;
            }
        }
        
        // Create new hook
        HookEntry* entry = &g_hooks[g_hook_count];
        memset(entry, 0, sizeof(HookEntry));
        
        entry->address = addr;
        strncpy(entry->name, name, sizeof(entry->name) - 1);
        entry->callback = (void*)generic_hook_callback;
        entry->thunk = g_thunk_table[g_hook_count].thunk;
        
        // If address is relative, add module base
        if (addr < 0x100000000) {
            addr += g_module_base;
        }
        
        entry->hook.target_addr = addr;
        entry->hook.user_impl = entry->callback;
        entry->hook.user_thunk = entry->thunk;
        
        int result = mh_install(&entry->hook);
        if (result != 0) {
            snprintf(response, sizeof(response), "ERROR: Failed to install hook at 0x%lX (error %d)\n", addr, result);
            pthread_mutex_unlock(&g_hook_mutex);
            send_response(client_fd, response);
            return;
        }
        
        // Bind thunk slot
        mh_bind_thunk_slot(g_thunk_table[g_hook_count].slot, entry->hook.tramp_mem);
        
        entry->active = true;
        g_hook_count++;
        
        snprintf(response, sizeof(response), "OK: Hook installed at 0x%lX (%s)\n", addr, name);
        pthread_mutex_unlock(&g_hook_mutex);
        send_response(client_fd, response);
        
        mh_log("[HookServer] Installed hook at 0x%lX (%s)\n", addr, name);
    }
    else if (strncmp(cmd, "unhook ", 7) == 0) {
        const char* addr_str = cmd + 7;
        uint64_t addr = 0;
        
        if (sscanf(addr_str, "0x%lx", &addr) != 1) {
            snprintf(response, sizeof(response), "ERROR: Invalid address format\n");
            send_response(client_fd, response);
            return;
        }
        
        pthread_mutex_lock(&g_hook_mutex);
        
        bool found = false;
        for (int i = 0; i < g_hook_count; i++) {
            if (g_hooks[i].address == addr && g_hooks[i].active) {
                mh_remove(&g_hooks[i].hook);
                g_hooks[i].active = false;
                found = true;
                snprintf(response, sizeof(response), "OK: Hook removed from 0x%lX\n", addr);
                break;
            }
        }
        
        if (!found) {
            snprintf(response, sizeof(response), "ERROR: No hook found at 0x%lX\n", addr);
        }
        
        pthread_mutex_unlock(&g_hook_mutex);
        send_response(client_fd, response);
    }
    else if (strcmp(cmd, "list\n") == 0 || strcmp(cmd, "list") == 0) {
        pthread_mutex_lock(&g_hook_mutex);
        
        snprintf(response, sizeof(response), "Active hooks (%d):\n", g_hook_count);
        send_response(client_fd, response);
        
        for (int i = 0; i < g_hook_count; i++) {
            if (g_hooks[i].active) {
                snprintf(response, sizeof(response), "  0x%lX - %s\n", 
                    g_hooks[i].address, g_hooks[i].name);
                send_response(client_fd, response);
            }
        }
        
        pthread_mutex_unlock(&g_hook_mutex);
    }
    else if (strcmp(cmd, "help\n") == 0 || strcmp(cmd, "help") == 0) {
        const char* help = 
            "Hook Server Commands:\n"
            "  hook log 0xADDRESS [name] - Install hook at address\n"
            "  unhook 0xADDRESS          - Remove hook at address\n"
            "  list                      - List all active hooks\n"
            "  help                      - Show this help\n"
            "\n"
            "Example: hook log 0x6B73C4 playback_control\n";
        send_response(client_fd, help);
    }
    else {
        snprintf(response, sizeof(response), "ERROR: Unknown command. Type 'help' for commands.\n");
        send_response(client_fd, response);
    }
}

//==============================================================================
// Server Thread
//==============================================================================
void* server_thread_func(void* arg) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len;
    
    mh_log("[HookServer] Starting server on port %d\n", SERVER_PORT);
    
    // Create socket
    g_server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_sockfd < 0) {
        mh_log("[HookServer] Failed to create socket\n");
        return NULL;
    }
    
    // Allow reuse of address
    int opt = 1;
    setsockopt(g_server_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind to port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (bind(g_server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        mh_log("[HookServer] Failed to bind to port %d\n", SERVER_PORT);
        close(g_server_sockfd);
        return NULL;
    }
    
    // Listen
    if (listen(g_server_sockfd, 5) != 0) {
        mh_log("[HookServer] Failed to listen\n");
        close(g_server_sockfd);
        return NULL;
    }
    
    mh_log("[HookServer] Server listening on port %d\n", SERVER_PORT);
    
    // Accept clients
    addr_len = sizeof(client_addr);
    while (g_server_running) {
        int client_fd = accept(g_server_sockfd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (g_server_running) {
                mh_log("[HookServer] Failed to accept client\n");
            }
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        mh_log("[HookServer] Client connected from %s\n", client_ip);
        
        // Send welcome message
        const char* welcome = "Hook Server v7.0 - Type 'help' for commands\n> ";
        write(client_fd, welcome, strlen(welcome));
        
        // Read commands from client
        char cmd_buffer[MAX_CMD_SIZE];
        while (g_server_running) {
            memset(cmd_buffer, 0, sizeof(cmd_buffer));
            ssize_t bytes_read = read(client_fd, cmd_buffer, sizeof(cmd_buffer) - 1);
            
            if (bytes_read <= 0) {
                mh_log("[HookServer] Client disconnected\n");
                break;
            }
            
            // Process command
            process_hook_command(client_fd, cmd_buffer);
            
            // Send prompt
            write(client_fd, "> ", 2);
        }
        
        close(client_fd);
    }
    
    close(g_server_sockfd);
    return NULL;
}

//==============================================================================
// Plugin Interface
//==============================================================================
extern "C" {

s32 attr_public plugin_load(s32 argc, const char* argv[]) {
    // Get module info
    OrbisKernelModuleInfo mi;
    mi.size = sizeof(mi);
    if (!get_module_info(mi, "eboot.bin", &g_module_base, &g_module_size)) {
        mh_log("[HookServer] Failed to get module info\n");
        return -1;
    }
    
    mh_log("[HookServer] Module base: 0x%lX, size: 0x%X\n", g_module_base, g_module_size);
    
    // Start server thread
    g_server_running = true;
    if (pthread_create(&g_server_thread, NULL, server_thread_func, NULL) != 0) {
        mh_log("[HookServer] Failed to create server thread\n");
        return -1;
    }
    
    mh_log("[HookServer] Plugin loaded successfully\n");
    return 0;
}

s32 attr_public plugin_unload(s32 argc, const char* argv[]) {
    mh_log("[HookServer] Unloading plugin...\n");
    
    // Stop server
    g_server_running = false;
    if (g_server_sockfd >= 0) {
        shutdown(g_server_sockfd, SHUT_RDWR);
        close(g_server_sockfd);
    }
    
    // Wait for server thread
    pthread_join(g_server_thread, NULL);
    
    // Remove all hooks
    pthread_mutex_lock(&g_hook_mutex);
    for (int i = 0; i < g_hook_count; i++) {
        if (g_hooks[i].active) {
            mh_remove(&g_hooks[i].hook);
        }
    }
    pthread_mutex_unlock(&g_hook_mutex);
    
    mh_log("[HookServer] Plugin unloaded\n");
    return 0;
}

s32 attr_module_hidden module_start(s64 argc, const void *args) {
    return 0;
}

s32 attr_module_hidden module_stop(s64 argc, const void *args) {
    return 0;
}

} // extern "C"