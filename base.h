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

#define RELEASED_CTX_TIMEOUT 5      // 10 second
#endif //DPI_TEST_BASE_H
