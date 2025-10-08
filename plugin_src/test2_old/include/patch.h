#pragma once

#include <Common.h>
#include "plugin_common.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned char *hexstrtochar2(const char *hexstr, s64 *size);
void sys_proc_rw(u64 address, void *data, u64 length);
void sys_proc_ro(u64 address, void *data, u64 length);
bool hex_prefix(const char *str);

#ifdef __cplusplus
}
#endif

// http://www.cse.yorku.ca/~oz/hash.html
#ifdef __cplusplus
constexpr inline u64 djb2_hash(const char *str)
{
    u64 hash = 5381;
    u32 c = 0;
    while ((c = *str++))
        hash = hash * 33 ^ c;
    return hash;
}
#else
static inline u64 djb2_hash(const char *str);
#endif

#ifdef __cplusplus
extern "C" {
#endif

u64 patch_hash_calc(const char *title, const char *name, const char *app_ver,
                    const char *title_id, const char *elf);
void patch_data1(const char* patch_type_str, u64 addr, const char *value, uint32_t source_size, uint64_t jump_target);

#ifdef __cplusplus
}
#endif
