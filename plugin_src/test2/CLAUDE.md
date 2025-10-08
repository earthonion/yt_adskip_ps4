# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a GoldHEN plugin for PS4 that blocks ads and skips sponsored segments (via SponsorBlock) in the YouTube Cobalt app (CUSA01015, v02.32). The plugin uses function hooking to inject JavaScript into the YouTube app's HTML script execution engine.

**Key constraint**: This plugin must work with both full jailbreak solutions (lapse) AND minimal exploits (PPPwn + GoldHEN), which have different memory protection capabilities.

## Build System

### Standard Build
```bash
./build.sh
```
This builds the release version and uploads it via FTP to the PS4 at `192.168.0.106:2121`.

### Debug Build
```bash
DEBUG=1 ./build.sh
```
**IMPORTANT**: The Makefile builds to different directories based on DEBUG flag:
- Release: `../../bin/plugins/prx_final/test2.prx`
- Debug: `../../bin/plugins/prx_debug/test2.prx`

**BUG**: `build.sh` always uploads from `prx_final/`, so debug builds must be manually uploaded:
```bash
curl -T ../../bin/plugins/prx_debug/test2.prx ftp://192.168.0.106:2121/data/GoldHEN/plugins/test2.prx
```

### Build Environment Requirements
- `$OO_PS4_TOOLCHAIN` environment variable must be set (OpenOrbis PS4 Toolchain)
- `$GOLDHEN_SDK` environment variable must be set (GoldHEN Plugins SDK)

## Architecture

### Core Components

#### 1. Mini-Hook Library (`mini_hook.c` + `mini_hook.h`)
Custom function hooking implementation that:
- Uses HDE64 disassembler to calculate safe instruction boundaries
- Creates trampolines to preserve original function behavior
- Supports two modes:
  - **THUNK mode**: Assembly bridge → user callback (used by this plugin)
  - **WRAPPER mode**: Direct C callback

**Critical implementation details**:
- Trampolines require RWX (read-write-execute) memory
- Must use standard POSIX `mmap()` and `munmap()`, NOT `sceKernelMmap()`
- Uses `sys_proc_rw()` (syscall 608) to write trampoline code (provided by GoldHEN)
- Logging uses `klog()` to ensure visibility in PS4 debug output

#### 2. JavaScript Injection (`main.cpp`)
- Hooks `HTMLScriptExecute` function at address `0x0097fb40`
- Injects ~3.5KB JavaScript payload that:
  - Detects and skips video ads
  - Integrates with SponsorBlock via local HTTP proxy
  - Shows native YouTube TV toast notifications

**Script extraction logic**:
- YouTube passes script content via complex C++ string objects
- Plugin uses pattern matching to locate string data/size/capacity fields
- Learns the layout at runtime (fallback to offset 0x8 if pattern fails)
- Once layout is learned, subsequent scripts are extracted faster

#### 3. SponsorBlock Proxy Server (`proxy.cpp`)
HTTP server on `localhost:4040` that:
- Bridges Cobalt browser to SponsorBlock API (bypasses XHR restrictions)
- Uses PS4 native networking: `sceNet`, `sceHttp`, `sceSsl`
- Runs in background thread
- Parses JSON responses manually (no JSON library available)

#### 4. Memory Patching (`patch.cpp`)
Provides `sys_proc_rw()` wrapper for kernel memory read/write via syscall 608.
This is only available when GoldHEN is loaded.

### Hook Flow

1. **Plugin loads** → `plugin_load()` called by GoldHEN
2. **Pattern scan** → Locates `HTMLScriptExecute` function in YouTube binary
3. **Hook installation** → `mh_install()` creates hook:
   ```
   Target function → JMP to thunk → User callback → Trampoline → Original code
   ```
4. **Every script execution** → Callback intercepts, inspects, potentially injects payload
5. **Direct injection** → After payload injected once, subsequent calls pass through

### Thunk Assembly Bridge

The plugin uses `MH_DEFINE_THUNK` macro to generate assembly thunks:
```cpp
MH_DEFINE_THUNK(execute, my_HTMLScriptExecute)
```
This creates:
- `__mh_thunk_execute`: Assembly entry point that preserves registers
- `__mh_tramp_slot_execute`: RIP-relative pointer to trampoline
- Bridge to `my_HTMLScriptExecute(void* self, long arg2, uint64_t arg3, char is_external)`

## Critical Compatibility Notes

### PPPwn vs Lapse Differences

**Lapse (full jailbreak)**:
- Applies all kernel patches including RWX memory support
- Everything works out of the box

**PPPwn + GoldHEN**:
- PPPwn is minimal exploit (no kexec, no full kernel patches)
- GoldHEN provides syscall 608 (`sys_proc_rw`) and RWX patches
- Plugin depends on GoldHEN being loaded first

**Why standard mmap() matters**:
- `sceKernelMmap()` has different parameter ordering and may return invalid addresses
- Standard POSIX `mmap()` is more reliable with GoldHEN's patches
- Must check for `MAP_FAILED` (-1), not just NULL

### Common Crash Pattern

If you see:
```
page fault (user read instruction, protection violation)
fault address: 0000000200014000
```

This means:
1. Hook installed successfully
2. Trampoline allocated but doesn't have execute permissions
3. Either:
   - mmap() returned invalid address
   - RWX kernel patches not applied
   - Using wrong mmap API

### File Synchronization Issue

**IMPORTANT**: The plugin has TWO copies of mini_hook.c:
- `/home/ryan/code/ps4/GoldHEN_Plugins_Repository/plugin_src/yt_adblock/source/mini_hook.c`
- `/home/ryan/code/ps4/GoldHEN_Plugins_Repository/plugin_src/test2/source/mini_hook.c`

Changes to one do NOT automatically propagate to the other. When modifying the hook implementation, update BOTH files.

## Testing Workflow

1. Make code changes
2. Build: `DEBUG=1 ./build.sh`
3. Manually upload debug build (see above)
4. Launch YouTube on PS4
5. Check PS4 kernel logs for `[minihook]` debug output
6. Look for crash dumps in kernel output

## Toast Notifications

The plugin shows native YouTube TV notifications via `sceKernelSendNotificationRequest()`:
- Icon URI: `cxml://psnotification/tex_icon_system`
- Used to confirm plugin loaded and show SponsorBlock status
- Implementation in `util.cpp::final_notify()`

## Address Resolution

The plugin uses pattern scanning to locate `HTMLScriptExecute`:
- Pattern: `HTML_EXECUTE_SIG` (defined in main.cpp)
- Offset: `HTML_EXECUTE_SIG_OFFSET`
- Fallback: `0x0097fb40` (hardcoded for YouTube v02.32)

If YouTube app updates, the pattern or fallback address may need adjustment.
