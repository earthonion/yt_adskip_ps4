
#pragma once
#include "mini_hook.h"
#ifndef MH_MAX_PROBE_SLOTS
#define MH_MAX_PROBE_SLOTS 32
#endif
#ifdef __cplusplus
extern "C" {
#endif

typedef void (*mh_vtprobe_cb)(int slot, void *orig, void *self);
int mh_vtprobe_install(uintptr_t **vt_ptr, int slots, mh_vtprobe_cb cb, mh_hook_t *hooks_out);
void mh_vtprobe_remove(mh_hook_t *hooks, int slots);

#ifdef __cplusplus
}
#endif
