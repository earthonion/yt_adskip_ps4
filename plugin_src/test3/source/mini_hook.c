#include "mini_hook.h"
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>


void* mh_trampoline_of(mh_hook_t *h) { return h ? h->tramp_mem : NULL; }
int   mh_is_installed(mh_hook_t *h)  { return h && h->installed; }

// ---- Logging ---------------------------------------------------------------
void mh_log(const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    sceKernelDebugOutText(0, buf);
}

void mh_bind_thunk_slot(void **slot_addr, void *trampoline) {
    *slot_addr = trampoline;
}

// ---- Disassembly helper ----------------------------------------------------
size_t mh_calc_prologue_len(uintptr_t addr, size_t min_size) {
    size_t total = 0;
    while (total < min_size && total < MH_MAX_PROLOGUE) {
        hde64s hs;
        uint32_t len = hde64_disasm((void *)(addr + total), &hs);
        if (hs.flags & F_ERROR || len == 0) {
            mh_log("[mini_hook] HDE64 decode error.\n");
            return 0;
        }
        total += len;
    }
    return (total >= min_size) ? total : 0;
}

// ---- Internal: write absolute RIP-relative JMP stub ------------------------
// Encoding: FF 25 00 00 00 00  [qword target]
// Size: 14 bytes; write NOPs to pad if needed.
static void emit_abs_jmp_stub(uint8_t *dst, uint64_t target) {
    dst[0] = 0xFF; dst[1] = 0x25; dst[2] = 0; dst[3] = 0; dst[4] = 0; dst[5] = 0;
    memcpy(dst + 6, &target, sizeof(target));
}

// ---- Install ---------------------------------------------------------------
int mh_install(mh_hook_t *h) {
    //if (!h || !h->target_addr || !h->user_impl) return -1;
    
    // After — allow wrapper (no user_impl) and thunk (both provided)
    if (!h || !h->target_addr){// || !h->user_thunk) {
        mh_log("[mini_hook] bad args: h=%p tgt=%p thunk=%p impl=%p\n",
           (void*)h, (void*)h->target_addr, h ? h->user_thunk : 0, h ? h->user_impl : 0);
        return -1;
    }
    if (h->installed) return 0;

    // 1) Determine how many bytes to steal (>= 14 for abs jmp)
    size_t stolen = mh_calc_prologue_len(h->target_addr, 14);
    if (!stolen || stolen > MH_MAX_PROLOGUE) {
        mh_log("[mini_hook] invalid prologue size (%zu).\n", stolen);
        return -2;
    }
    h->stolen_len = stolen;

    // 2) Save original bytes
    memcpy(h->original, (void *)h->target_addr, stolen);

    // 3) Allocate executable trampoline page
    void *tramp = NULL;
    int ret = sceKernelMmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                            0x1000 | 0x2, -1, 0, &tramp); // MAP_PRIVATE|MAP_ANON
    if (ret != 0 || !tramp) {
        mh_log("[mini_hook] mmap trampoline failed: 0x%X\n", ret);
        return -3;
    }
    h->tramp_mem = tramp;

    // 4) Build trampoline: [stolen bytes] + [abs jmp back to target+stolen]
    uint8_t tramp_buf[MH_MAX_PROLOGUE + 14] = {0};
    memcpy(tramp_buf, h->original, stolen);

    uint64_t return_addr = (uint64_t)(h->target_addr + stolen);
    emit_abs_jmp_stub(tramp_buf + stolen, return_addr);

    sys_proc_rw((uintptr_t)tramp, tramp_buf, stolen + 14);
    h->tramp_size = stolen + 14;

    // 5) Decide patch entry point:
    //    - Thunk mode: entry = user_thunk (assembly thunk does pre-work, tail-jumps to tramp)
    //    - Wrapper mode: entry = user_impl (C wrapper calls h->orig_fn to reach tramp/original)
    void* entry;
    if (h->user_thunk) {
        // ---- Thunk mode
        entry        = h->user_thunk;
        h->orig_fn   = tramp;             // still expose tramp as callable if someone wants it
        h->mode      = MH_MODE_THUNK;
    } else {
        // ---- Wrapper mode
        entry        = h->user_impl;      // patch jumps straight to user C function
        h->orig_fn   = tramp;             // user calls this to reach original
        h->mode      = MH_MODE_WRAPPER;
    }

    // 6) Patch the target prologue with absolute jmp to 'entry'
    uint8_t patch[MH_MAX_PROLOGUE] = {0};
    emit_abs_jmp_stub(patch, (uint64_t)entry);
    if (stolen > 14) memset(patch + 14, 0x90, stolen - 14);

    sys_proc_rw(h->target_addr, patch, stolen);

    // 7) Thunk mode only: user’s thunk ends with `jmp *slot(%rip)`. Bind slot -> trampoline.
    if (h->mode == MH_MODE_THUNK && h->thunk_slot) {
        // write the trampoline pointer into the slot
        *(volatile void**)h->thunk_slot = h->tramp_mem;
        // (If you can’t directly write here, add a proc_rw variant to do so safely.)
    }

    h->installed = true;
    return 0;
}

// ---- Remove ---------------------------------------------------------------
int mh_remove(mh_hook_t *h) {
    if (!h || !h->installed) return 0;

    // Restore original bytes
    sys_proc_rw(h->target_addr, h->original, h->stolen_len);

    // Unmap trampoline
    if (h->tramp_mem) {
        sceKernelMunmap(h->tramp_mem, 4096);
        h->tramp_mem = NULL;
    }
    h->orig_fn = NULL;
    h->installed = false;
    return 0;
}
