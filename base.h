//
// Created by tanchao on 2022/6/23.
//

#ifndef DPI_TEST_BASE_H
#define DPI_TEST_BASE_H

#include <inttypes.h>
#include "utils/timer_queue.h"
#include "urcu/hlist.h"
#include "defs.h"
#include "utils/rcu_map.h"

#define max(x,y) (((x)>(y))?(x):(y))
#define min(x,y) (((x)<(y))?(x):(y))

//分支转移的信息提供给编译器，减少指令跳转带来的性能下降
#ifndef likely
# define likely(x)        __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
# define unlikely(x)        __builtin_expect(!!(x), 0)
#endif


typedef struct rate_limiter_ {
    uint16_t dur;             // in second
    uint16_t dur_cnt_limit;
    uint32_t start;
    uint32_t cnt;
    uint32_t total_drop;
    uint32_t total_pass;
} dp_rate_limter_t;

#endif //DPI_TEST_BASE_H
