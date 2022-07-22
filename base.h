//
// Created by tanchao on 2022/6/23.
//

#ifndef DPI_TEST_BASE_H
#define DPI_TEST_BASE_H

#include <inttypes.h>
#include "defs.h"
#include "base/config/config.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "base/timer_queue.h"
#include "base/rcu_map.h"
#include "urcu/hlist.h"
#ifdef __cplusplus
}
#endif


#define max(x,y) (((x)>(y))?(x):(y))
#define min(x,y) (((x)<(y))?(x):(y))

//分支转移的信息提供给编译器，减少指令跳转带来的性能下降
#ifndef likely
# define likely(x)        __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)        __builtin_expect(!!(x), 0)
#endif

static uint32_t g_seconds;
static time_t g_start_time;

typedef struct rate_limiter_ {
    uint16_t dur;             // in second
    uint16_t dur_cnt_limit;
    uint32_t start;
    uint32_t cnt;
    uint32_t total_drop;
    uint32_t total_pass;
} dp_rate_limter_t;

extern int g_stats_slot;
time_t get_current_time();


typedef struct dp_mnt_shm_ {
    uint32_t dp_hb[MAX_DP_THREADS];
    bool dp_active[MAX_DP_THREADS];
} dp_mnt_shm_t;
#endif //DPI_TEST_BASE_H
