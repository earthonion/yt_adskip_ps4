//==============================================================================
// PS4 PRX: CreatePlayer hook + SbPlayer probe
// - Safe capture of SbPlayer via vt slot probe (naked thunk, reads %rdi only)
// - Marshal GetInfo on owner thread to SetRate(0) -> Seek(0) -> SetRate(1)
// - Pure C (no <atomic>, no STL)
//==============================================================================
#include "plugin_common.h"
#include "utils.h"
#include "mini_hook.h"

#include <orbis/libkernel.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#define MH_LOG(fmt, ...) mh_log("[minihook] " fmt, ##__VA_ARGS__)

// Toggle: default = marshal to owner thread via GetInfo wrapper
#ifndef NO_MARSHAL_TO_OWNER
#define MARSHAL_TO_OWNER 1
#else
#define MARSHAL_TO_OWNER 0
#endif
//------------------------------------------------------------------------------
// Offsets you provided
//------------------------------------------------------------------------------
#define OFFS_CREATE_PLAYER   0x006d44a0   // void CreatePlayer(long, u64)
#define OFFS_SBPLAYER_PROBE  0x006d12b0   // vt slot probe (captures SbPlayer via %rdi)

#define PLUGIN_NAME_STR      "minihook_example"
#define PLUGIN_DESC_STR      "Hook CreatePlayer + probe SbPlayer; loop video at 60s"
#define PLUGIN_AUTH_STR      "earthonion"
#define PLUGIN_VER_HEX       0x00000604

//------------------------------------------------------------------------------
// Minimal Starboard-ish types
//------------------------------------------------------------------------------
typedef struct SbPlayerPrivate* SbPlayer;

typedef struct SbPlayerInfo {
  int64_t current_media_timestamp;   // µs
  int64_t duration;                  // µs
  int64_t start_date;                // µs since 1601-01-01
  int     frame_width;
  int     frame_height;
  bool    is_paused;
  double  volume;
  int     total_video_frames;
  int     dropped_video_frames;
  int     corrupted_video_frames;
  double  playback_rate;
} SbPlayerInfo;

//------------------------------------------------------------------------------
// Metadata
//------------------------------------------------------------------------------
attr_public const char *g_pluginName    = PLUGIN_NAME_STR;
attr_public const char *g_pluginDesc    = PLUGIN_DESC_STR;
attr_public const char *g_pluginAuth    = PLUGIN_AUTH_STR;
attr_public u32         g_pluginVersion = PLUGIN_VER_HEX;

//------------------------------------------------------------------------------
// Globals (pure C)
//------------------------------------------------------------------------------
static SbPlayer g_player        = NULL;
static volatile int g_player_ready = 0;
static int      g_player_logged = 0;
static int      g_player_init_done = 0;
static int      g_ticket        = 1;   // monotonic ticket
static int      g_hook_thread_started = 0;  // marshal helper thread once
#if !MARSHAL_TO_OWNER
static int      g_loop_started  = 0;   // for polling mode (thread spawn)
#endif
static int      g_loop_armed    = 1;   // hysteresis guard
static uint64_t g_owner_tid     = 0;
#if MARSHAL_TO_OWNER
static int      g_info_poll_started = 0;
#endif

static inline int      next_ticket(void){ return __sync_fetch_and_add(&g_ticket, 1); }
static inline int      test_and_set_once(int* p){ return __sync_lock_test_and_set(p, 1); }
static inline void     clear_flag(int* p){ __sync_lock_release(p); }
static inline uint64_t cur_tid(void){ return (uint64_t)pthread_self(); }
static const int64_t   LOOP_THRESHOLD_US = 60LL * 1000000LL;

#define MH_DEBUG_KICK_SEEK 0

static void log_bytes16(const char *tag, const void *addr){
  const unsigned char *b = (const unsigned char *)addr;
  char hex[3 * 16 + 1];
  size_t offset = 0;
  for (int i = 0; i < 16 && offset < sizeof(hex); ++i){
    offset += snprintf(hex + offset, sizeof(hex) - offset, "%02X%s",
                       b[i], (i == 15 ? "" : " "));
  }
  hex[sizeof(hex) - 1] = '\0';
  MH_LOG("%s %p : %s\n", tag, addr, hex);
}

static void ensure_loop_thread(void);
static void on_player_ready(SbPlayer player);
#if MARSHAL_TO_OWNER
static void* info_poll_thread(void*);
#endif

#if MH_DEBUG_KICK_SEEK
static void* debug_seek_thread(void*);
static int      g_debug_seek_scheduled = 0;
#endif
//------------------------------------------------------------------------------
// Vtable helpers / typedefs
//------------------------------------------------------------------------------
static inline uintptr_t* vtable_of(SbPlayer p){ return *(uintptr_t**)p; }

enum {
  VTBL_OFFSET_TO_TOP = 0, VTBL_TYPEINFO = 1,
  VTBL_DTOR_NONDEL = 2,   VTBL_DTOR_DEL = 3,
  VTBL_SEEK = 4,          VTBL_WRITESAMPLES = 5,
  VTBL_WRITE_EOS = 6,     VTBL_SET_BOUNDS = 7,
  VTBL_GET_INFO = 8,      VTBL_SET_PAUSE = 9,
  VTBL_SET_RATE = 10,     VTBL_SET_VOLUME = 11,
  VTBL_GET_DECODE_TGT=12, VTBL_GET_AUDIO_CFG=13,
};

typedef void (*SeekFn)(SbPlayer, int64_t, int);
typedef void (*SetPlaybackRateFn)(SbPlayer, double);
typedef void (*GetInfoFn)(SbPlayer, SbPlayerInfo*);
typedef void (*SetBoundsFn)(SbPlayer, int, int, int, int, int);
typedef int SbMediaType;  // minimal placeholder

typedef struct SbPlayerSampleInfo {
  void*   buffer;    // 0x00
  size_t  size;      // 0x08
  int64_t pts;       // 0x10
  int64_t dts;       // 0x18
  int     type;      // 0x20 (usage dependent)
  int     frames;    // 0x24
  // remaining fields ignored
} SbPlayerSampleInfo;

typedef void (*WriteSamplesFn)(SbPlayer, SbMediaType, const SbPlayerSampleInfo*, int);

static void dump_vtable_once(SbPlayer p, int N){
  static int dumped = 0;
  if (dumped || !p) return; dumped = 1;
  uintptr_t* vt = vtable_of(p);
  MH_LOG("[vtable] vptr=%p\n", (void*)vt);
  for (int i=0;i<N;++i) MH_LOG("  vt[%2d] = %p\n", i, (void*)vt[i]);
}

#if !MARSHAL_TO_OWNER
static void do_get_info_from_vt(SbPlayer p, uintptr_t* vt, SbPlayerInfo* out){
  ((GetInfoFn)vt[VTBL_GET_INFO])(p, out);
}
#endif
static void do_set_rate_from_vt(SbPlayer p, uintptr_t* vt, double r){
  ((SetPlaybackRateFn)vt[VTBL_SET_RATE])(p, r);
}
static void do_seek_from_vt(SbPlayer p, uintptr_t* vt, int64_t ts, int ticket){
  ((SeekFn)vt[VTBL_SEEK])(p, ts, ticket);
}

static void perform_loop_actions(SbPlayer player, uintptr_t* vt){
  if (!player || !vt) return;
  int ticket = next_ticket();
  MH_LOG("[loop] rate->0, seek->0, ticket=%d, rate->1\n", ticket);
  do_set_rate_from_vt(player, vt, 0.0);
  do_seek_from_vt(player, vt, 0, ticket);
  do_set_rate_from_vt(player, vt, 1.0);
}

static void maybe_trigger_loop(SbPlayer player, uintptr_t* vt, int64_t current_ts){
  if (!player || !vt) return;
  if (current_ts >= LOOP_THRESHOLD_US){
    if (g_loop_armed){
      g_loop_armed = 0;
      perform_loop_actions(player, vt);
    }
  } else {
    g_loop_armed = 1;
  }
}

#if !MARSHAL_TO_OWNER
static void log_player_once(SbPlayer player){
  if (!player || g_player_logged) return;
  g_player_logged = 1;
  MH_LOG("[hook] captured SbPlayer: %p\n", (void*)player);
  on_player_ready(player);
}
#endif

//------------------------------------------------------------------------------
// MARSHAL MODE: clone vtable, wrap GetInfo (runs on owner thread naturally)
//------------------------------------------------------------------------------
#if MARSHAL_TO_OWNER
static uintptr_t* g_vt_clone     = NULL;
static GetInfoFn  g_orig_GetInfo = NULL;
static SetBoundsFn g_orig_SetBounds = NULL;
static SetPlaybackRateFn g_orig_SetRate = NULL;
static WriteSamplesFn g_orig_WriteSamples = NULL;

static void assert_slot_is_getinfo(uintptr_t* vt) {
    // Replace 0x6d1710 with whatever you printed as "orig=...." in your logs
    // or just log vt[VTBL_GET_INFO] once to confirm.
    MH_LOG("[check] vt[GET_INFO]=%p\n", (void*)vt[VTBL_GET_INFO]);
}

// Trampoline that calls original *without* changing arg registers.
static __thread int g_in_getinfo   = 0;
static __thread int g_in_setbounds = 0;
static __thread int g_in_setrate   = 0;
static __thread int g_in_writesamples = 0;

// Our vtable wrapper (runs on whichever thread the app calls GetInfo)
static void my_GetInfo_wrapper(SbPlayer self, SbPlayerInfo* out_info) {
    if (g_in_getinfo) {
        g_orig_GetInfo(self, out_info);
        return;
    }

    g_in_getinfo = 1;

    g_orig_GetInfo(self, out_info);

    dump_vtable_once(self, 16);

    int64_t ts = out_info->current_media_timestamp;
    MH_LOG("[GetInfo] tid=0x%llx ts=%lldus rate=%.2f paused=%d\n",
           (unsigned long long)cur_tid(),
           (long long)ts,
           out_info->playback_rate,
           (int)out_info->is_paused);

    maybe_trigger_loop(self, g_vt_clone, ts);

    g_in_getinfo = 0;
}

static void my_SetBounds_wrapper(SbPlayer self, int z, int x, int y, int w, int h) {
    g_orig_SetBounds(self, z, x, y, w, h);

    if (g_in_setbounds) return;
    g_in_setbounds = 1;

    SbPlayerInfo info; memset(&info, 0, sizeof(info));
    g_orig_GetInfo(self, &info);

    MH_LOG("[SB] tid=0x%llx ts=%lldus rate=%.2f paused=%d\n",
           (unsigned long long)cur_tid(),
           (long long)info.current_media_timestamp,
           info.playback_rate,
           (int)info.is_paused);

    maybe_trigger_loop(self, g_vt_clone, info.current_media_timestamp);

    g_in_setbounds = 0;
}

static void my_SetRate_wrapper(SbPlayer self, double rate) {
    g_orig_SetRate(self, rate);

    if (g_in_setrate) return;
    g_in_setrate = 1;

    SbPlayerInfo info; memset(&info, 0, sizeof(info));
    g_orig_GetInfo(self, &info);

    MH_LOG("[SR] tid=0x%llx rate=%.2f ts=%lldus paused=%d\n",
           (unsigned long long)cur_tid(),
           rate,
           (long long)info.current_media_timestamp,
           (int)info.is_paused);

    maybe_trigger_loop(self, g_vt_clone, info.current_media_timestamp);

    if (rate > 0.0) {
        if (!test_and_set_once(&g_info_poll_started)) {
            pthread_t tid; int err = pthread_create(&tid, NULL, info_poll_thread, NULL);
            MH_LOG("[poll] info thread %s (err=%d)\n", err ? "FAILED" : "OK", err);
            if (err) clear_flag(&g_info_poll_started);
        }
    }

    g_in_setrate = 0;
}

static void my_WriteSamples_wrapper(SbPlayer self, SbMediaType sample_type, const SbPlayerSampleInfo* infos, int count) {
    g_orig_WriteSamples(self, sample_type, infos, count);

    if (g_in_writesamples || !infos || count <= 0) return;
    g_in_writesamples = 1;

    SbPlayerInfo info; memset(&info, 0, sizeof(info));
    g_orig_GetInfo(self, &info);

    const SbPlayerSampleInfo* first = &infos[0];

    MH_LOG("[WS] tid=0x%llx media=%d count=%d frames=%d pts=%lld ts=%lldus rate=%.2f paused=%d\n",
           (unsigned long long)cur_tid(),
           sample_type,
           count,
           first->frames,
           (long long)first->pts,
           (long long)info.current_media_timestamp,
           info.playback_rate,
           (int)info.is_paused);

    maybe_trigger_loop(self, g_vt_clone, info.current_media_timestamp);

    g_in_writesamples = 0;
}
#else
//------------------------------------------------------------------------------
// POLLING MODE: simple background thread (1Hz), calls virtuals directly
//------------------------------------------------------------------------------
static void* loop_thread(void*){
  MH_LOG("[loop] started tid=0x%llx\n",(unsigned long long)cur_tid());
  sceKernelUsleep(300000);
  while(1){
    SbPlayer p = g_player;
    if (g_player_ready) log_player_once(p);
    if (!p){ sceKernelUsleep(500000); continue; }

    uintptr_t* vt = vtable_of(p);
    dump_vtable_once(p,16);

    SbPlayerInfo info; memset(&info,0,sizeof(info));
    do_get_info_from_vt(p, vt, &info);
    double sec = info.current_media_timestamp/1000000.0;
    MH_LOG("[info] ts=%lld µs (%.2f s) dur=%lld µs rate=%.2f paused=%d\n",
           (long long)info.current_media_timestamp, sec,
           (long long)info.duration, info.playback_rate, (int)info.is_paused);

    maybe_trigger_loop(p, vt, info.current_media_timestamp);
    sceKernelUsleep(1000000);
  }
  // return NULL;
}
#endif // MARSHAL_TO_OWNER

#if MARSHAL_TO_OWNER
static void* marshal_wait_thread(void*){
  MH_LOG("[hook] wait for SbPlayer tid=0x%llx\n", (unsigned long long)cur_tid());
  while (!g_player_ready) sceKernelUsleep(100000);
  SbPlayer p = g_player;
  if (p) on_player_ready(p);
  return NULL;
}

static void ensure_loop_thread(void){
  if (!test_and_set_once(&g_hook_thread_started)){
    pthread_t tid; int err = pthread_create(&tid, NULL, marshal_wait_thread, NULL);
    MH_LOG("[hook] marshal wait thread %s (err=%d)\n", err ? "FAILED":"OK", err);
    if (err) clear_flag(&g_hook_thread_started);
  }
}
#else
static void ensure_loop_thread(void){
  if (!test_and_set_once(&g_loop_started)){
    pthread_t tid; int err = pthread_create(&tid, NULL, loop_thread, NULL);
    MH_LOG("[loop] thread create %s (err=%d)\n", err ? "FAILED":"OK", err);
    if (err) clear_flag(&g_loop_started);
  }
}
#endif

static void on_player_ready(SbPlayer player){
  if (!player) return;
  if (test_and_set_once(&g_player_init_done)) return;
#if MARSHAL_TO_OWNER
  uintptr_t* orig_vt = vtable_of(player);
  const int N = 32;
  uintptr_t* clone = (uintptr_t*)malloc(N * sizeof(uintptr_t));
  if (clone){
    memcpy(clone, orig_vt, N * sizeof(uintptr_t));
    g_orig_GetInfo         = (GetInfoFn)orig_vt[VTBL_GET_INFO];
    g_orig_SetBounds       = (SetBoundsFn)orig_vt[VTBL_SET_BOUNDS];
    g_orig_SetRate         = (SetPlaybackRateFn)orig_vt[VTBL_SET_RATE];
    g_orig_WriteSamples    = (WriteSamplesFn)orig_vt[VTBL_WRITESAMPLES];
    clone[VTBL_GET_INFO]   = (uintptr_t)&my_GetInfo_wrapper;
    clone[VTBL_SET_BOUNDS] = (uintptr_t)&my_SetBounds_wrapper;
    clone[VTBL_SET_RATE]   = (uintptr_t)&my_SetRate_wrapper;
    clone[VTBL_WRITESAMPLES] = (uintptr_t)&my_WriteSamples_wrapper;
    *(uintptr_t**)player   = clone;
    g_vt_clone             = clone;
    MH_LOG("[hook] vtable cloned @%p, GetInfo %p->%p, SetBounds %p->%p, SetRate %p->%p, WriteSamples %p->%p\n",
           (void*)clone,
           (void*)g_orig_GetInfo,  (void*)&my_GetInfo_wrapper,
           (void*)g_orig_SetBounds,(void*)&my_SetBounds_wrapper,
           (void*)g_orig_SetRate,  (void*)&my_SetRate_wrapper,
           (void*)g_orig_WriteSamples, (void*)&my_WriteSamples_wrapper);
    assert_slot_is_getinfo(clone);
    log_bytes16("orig.getinfo", (void*)g_orig_GetInfo);
    log_bytes16("orig.setbounds", (void*)g_orig_SetBounds);
    log_bytes16("orig.setrate", (void*)g_orig_SetRate);
    log_bytes16("orig.writesamples", (void*)g_orig_WriteSamples);
    log_bytes16("wrapper.getinfo", (void*)&my_GetInfo_wrapper);
    log_bytes16("wrapper.setbounds", (void*)&my_SetBounds_wrapper);
    log_bytes16("wrapper.setrate", (void*)&my_SetRate_wrapper);
    log_bytes16("wrapper.writesamples", (void*)&my_WriteSamples_wrapper);
    log_bytes16("vtable.getinfo", (void*)clone[VTBL_GET_INFO]);
    log_bytes16("vtable.setbounds", (void*)clone[VTBL_SET_BOUNDS]);
    log_bytes16("vtable.setrate", (void*)clone[VTBL_SET_RATE]);
    log_bytes16("vtable.writesamples", (void*)clone[VTBL_WRITESAMPLES]);
#if MARSHAL_TO_OWNER
    if (!test_and_set_once(&g_info_poll_started)){
      pthread_t tid; int err = pthread_create(&tid, NULL, info_poll_thread, NULL);
      MH_LOG("[poll] info thread %s (err=%d)\n", err ? "FAILED" : "OK", err);
      if (err) clear_flag(&g_info_poll_started);
    }
#endif
#if MH_DEBUG_KICK_SEEK
    if (!g_debug_seek_scheduled){
      g_debug_seek_scheduled = 1;
      pthread_t tid; int err = pthread_create(&tid, NULL, debug_seek_thread, NULL);
      MH_LOG("[debug] manual seek thread %s (err=%d)\n", err ? "FAILED" : "OK", err);
      if (err) clear_flag(&g_debug_seek_scheduled);
    }
#endif
  } else {
    MH_LOG("[hook] vtable clone FAILED\n");
    clear_flag(&g_player_init_done);
  }
#else
  ensure_loop_thread();
#endif
}

//------------------------------------------------------------------------------
// HOOK 1: CreatePlayer — **do not** assume return; treat as void
//------------------------------------------------------------------------------
typedef void (*CreatePlayerFn)(long /*param1*/, uint64_t /*param2*/);
static CreatePlayerFn g_real_CreatePlayer = NULL;
static mh_hook_t      g_create_hook;

static void my_CreatePlayer(long param1, uint64_t param2){
  // call original first
  g_real_CreatePlayer(param1, param2);

  // Record owner thread; we *do not* try to read a return pointer here.
  g_owner_tid = cur_tid();
  MH_LOG("[hook] CreatePlayer called (owner tid=0x%llx)\n",
         (unsigned long long)g_owner_tid);
}

//------------------------------------------------------------------------------
// HOOK 2: SbPlayer probe — naked thunk captures %rdi then tail-jumps
//------------------------------------------------------------------------------
static mh_hook_t g_probe_hook;
static void *g_probe_tramp_slot = NULL;

__attribute__((naked)) static void sbplayer_probe_thunk(void){
  __asm__ volatile(
    "movq (%[gp]), %%rax\n"
    "test %%rax, %%rax\n"
    "jnz 1f\n"
    "test %%rdi, %%rdi\n"
    "jz 1f\n"
    "movq %%rdi, (%[gp])\n"
    "mfence\n"
    "movl $1, %[ready]\n"
    "1:\n"
    "mov %[slot], %%rax\n"
    "jmp *%%rax\n"
    :
    : [gp] "r" (&g_player),
      [ready] "m" (g_player_ready),
      [slot] "m" (g_probe_tramp_slot)
    : "rax", "memory", "cc"
  );
}

//------------------------------------------------------------------------------
// Lifecycle
//------------------------------------------------------------------------------
extern "C" {
    
s32 attr_public plugin_load(s32 argc, const char* argv[]){
  (void)argc; (void)argv;

  // Install CreatePlayer hook (void signature)
  memset(&g_create_hook, 0, sizeof(g_create_hook));
  g_create_hook.target_addr = OFFS_CREATE_PLAYER;
  g_create_hook.user_impl   = (void*)my_CreatePlayer;
  g_create_hook.user_thunk  = NULL;

  int r = mh_install(&g_create_hook);
  if (r){ MH_LOG("[hook] CreatePlayer install FAILED (%d)\n", r); return r; }
  g_real_CreatePlayer = (CreatePlayerFn)g_create_hook.orig_fn;
  MH_LOG("[hook] CreatePlayer installed. orig=%p\n", (void*)g_real_CreatePlayer);

  // Install SbPlayer probe hook (naked thunk)
  memset(&g_probe_hook, 0, sizeof(g_probe_hook));
  g_probe_hook.target_addr = OFFS_SBPLAYER_PROBE;
  g_probe_hook.user_impl   = NULL;
  g_probe_hook.user_thunk  = (void*)sbplayer_probe_thunk;
  g_probe_hook.thunk_slot  = &g_probe_tramp_slot;

  r = mh_install(&g_probe_hook);
  if (r){ MH_LOG("[hook] SbPlayer probe install FAILED (%d)\n", r); return r; }
  mh_bind_thunk_slot(&g_probe_tramp_slot, g_probe_hook.tramp_mem);
  MH_LOG("[hook] SbPlayer probe installed. tramp=%p slot=%p (marshal=%d)\n",
         g_probe_hook.orig_fn, g_probe_tramp_slot, (int)MARSHAL_TO_OWNER);

  ensure_loop_thread();

  return 0;
}

s32 attr_public plugin_unload(s32 argc, const char* argv[]){
  (void)argc; (void)argv;
  MH_LOG("[Plugin] Unloading...\n");
  mh_remove(&g_probe_hook);
  mh_remove(&g_create_hook);
  g_player = NULL;
  g_player_ready = 0;
  g_player_logged = 0;
  g_player_init_done = 0;
  g_loop_armed = 1;
  MH_LOG("[Plugin] Unloaded.\n");
  return 0;
}

s32 attr_module_hidden module_start(s64 argc, const void *args){ (void)argc; (void)args; return 0; }
s32 attr_module_hidden module_stop (s64 argc, const void *args){ (void)argc; (void)args; return 0; }

}
#if MH_DEBUG_KICK_SEEK
static void* debug_seek_thread(void*){
  MH_LOG("[debug] manual seek thread start tid=0x%llx\n", (unsigned long long)cur_tid());
  sceKernelUsleep(500000);
  SbPlayer p = g_player;
  if (!p) return NULL;
  uintptr_t* vt = g_vt_clone ? g_vt_clone : vtable_of(p);
  MH_LOG("[debug] manual perform_loop_actions via vt[SEEK]\n");
  perform_loop_actions(p, vt);
  return NULL;
}
#endif

#if MARSHAL_TO_OWNER
static void* info_poll_thread(void*){
  MH_LOG("[poll] info thread start tid=0x%llx\n", (unsigned long long)cur_tid());
  for (int attempts = 0; attempts < 240; ++attempts) {
    SbPlayer p = g_player;
    if (!p) break;
    uintptr_t* vt = g_vt_clone ? g_vt_clone : vtable_of(p);
    SbPlayerInfo info; memset(&info, 0, sizeof(info));
    g_orig_GetInfo(p, &info);
    MH_LOG("[poll] ts=%lldus rate=%.2f paused=%d\n", (long long)info.current_media_timestamp,
           info.playback_rate, (int)info.is_paused);
    maybe_trigger_loop(p, vt, info.current_media_timestamp);
    if (info.current_media_timestamp >= LOOP_THRESHOLD_US) break;
    sceKernelUsleep(250000);
  }
  clear_flag(&g_info_poll_started);
  MH_LOG("[poll] info thread exit\n");
  return NULL;
}
#endif
