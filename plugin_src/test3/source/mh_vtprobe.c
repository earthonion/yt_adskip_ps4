
#include "mh_vtprobe.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

typedef void (*slot_fn)(void);

typedef struct {
    uintptr_t **vt_ptr;
    mh_vtprobe_cb cb;
    mh_hook_t *hooks;
    int slots;
} vtprobe_state;

static vtprobe_state g_probe;

#define DECL_PROBE(N) \
    __attribute__((naked)) static void vtprobe_wrapper_##N(void) { \
        __asm__ volatile( \
            "push %%rax\n\t" \
            "mov %0, %%rax\n\t" \
            "mov %%rsp, %%rsi\n\t" \
            "call *%%rax\n\t" \
            "pop %%rax\n\t" \
            "mov %1, %%rax\n\t" \
            "jmp *%%rax\n" \
            : \
            : "r"(vtprobe_tramp_##N), "m"(g_probe.hooks[N].orig_fn) \
            : "rax", "rsi", "memory" \
        ); \
    }

#define DEF_TRAMP(N) \
    static void vtprobe_tramp_##N(void) { \
        slot_fn orig = (slot_fn)g_probe.hooks[N].orig_fn; \
        uintptr_t *vt = *g_probe.vt_ptr; \
        g_probe.cb(N, (void*)orig, (void*)vt[0]); \
    }

#define DECL_SLOT(N) \
    DEF_TRAMP(N)     \
    DECL_PROBE(N)

DECL_SLOT(0)  DECL_SLOT(1)  DECL_SLOT(2)  DECL_SLOT(3)
DECL_SLOT(4)  DECL_SLOT(5)  DECL_SLOT(6)  DECL_SLOT(7)
DECL_SLOT(8)  DECL_SLOT(9)  DECL_SLOT(10) DECL_SLOT(11)
DECL_SLOT(12) DECL_SLOT(13) DECL_SLOT(14) DECL_SLOT(15)
DECL_SLOT(16) DECL_SLOT(17) DECL_SLOT(18) DECL_SLOT(19)
DECL_SLOT(20) DECL_SLOT(21) DECL_SLOT(22) DECL_SLOT(23)
DECL_SLOT(24) DECL_SLOT(25) DECL_SLOT(26) DECL_SLOT(27)
DECL_SLOT(28) DECL_SLOT(29) DECL_SLOT(30) DECL_SLOT(31)

static slot_fn wrappers[MH_MAX_PROBE_SLOTS] = {
    vtprobe_wrapper_0,  vtprobe_wrapper_1,  vtprobe_wrapper_2,  vtprobe_wrapper_3,
    vtprobe_wrapper_4,  vtprobe_wrapper_5,  vtprobe_wrapper_6,  vtprobe_wrapper_7,
    vtprobe_wrapper_8,  vtprobe_wrapper_9,  vtprobe_wrapper_10, vtprobe_wrapper_11,
    vtprobe_wrapper_12, vtprobe_wrapper_13, vtprobe_wrapper_14, vtprobe_wrapper_15,
    vtprobe_wrapper_16, vtprobe_wrapper_17, vtprobe_wrapper_18, vtprobe_wrapper_19,
    vtprobe_wrapper_20, vtprobe_wrapper_21, vtprobe_wrapper_22, vtprobe_wrapper_23,
    vtprobe_wrapper_24, vtprobe_wrapper_25, vtprobe_wrapper_26, vtprobe_wrapper_27,
    vtprobe_wrapper_28, vtprobe_wrapper_29, vtprobe_wrapper_30, vtprobe_wrapper_31
};

int mh_vtprobe_install(uintptr_t **vt_ptr, int slots, mh_vtprobe_cb cb, mh_hook_t *hooks_out) {
    if (!vt_ptr || !cb || slots <= 0 || slots > MH_MAX_PROBE_SLOTS) return -1;
    g_probe.vt_ptr = vt_ptr;
    g_probe.cb = cb;
    g_probe.hooks = hooks_out;
    g_probe.slots = slots;
    memset(hooks_out, 0, sizeof(mh_hook_t)*slots);

    for (int i = 0; i < slots; ++i) {
        mh_hook_t *h = &hooks_out[i];
        h->target_addr = (*vt_ptr)[i];
        h->user_impl = (void*)wrappers[i];
        if (mh_install(h)) return -1;
    }
    return 0;
}

void mh_vtprobe_remove(mh_hook_t *hooks, int slots) {
    if (!hooks) return;
    for (int i = 0; i < slots; ++i) mh_remove(&hooks[i]);
    memset(&g_probe, 0, sizeof(g_probe));
}
