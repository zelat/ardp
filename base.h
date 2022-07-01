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

//定义dp线程结构
typedef struct dp_thread_data_ {
    int epoll_fd;                      //epoll句柄
    struct cds_hlist_head ctx_list;    //使用线性列表作为列表头
    timer_queue_t ctx_free_list;       //时间队列
    struct dp_context_ *ctx_inline;    //
    pthread_mutex_t ctrl_dp_lock;      //线程互斥锁
    int ctrl_req_evfd;                 //控制器请求句柄
    uint32_t ctrl_req;
#define MAX_LOG_ENTRIES 128
#define LOG_ENTRY_SIZE (sizeof(DPMsgHdr) + sizeof(DPMsgThreatLog))
    uint32_t log_writer;
    uint32_t log_reader;
    uint8_t log_ring[MAX_LOG_ENTRIES][LOG_ENTRY_SIZE];
    rcu_map_t conn4_map[2];
    uint32_t conn4_map_cnt[2];
    dp_rate_limter_t conn4_rl;
#define CONNECT_RL_DUR  2
#define CONNECT_RL_CNT  400
    uint32_t conn4_map_cur;
} dp_thread_data_t;

#endif //DPI_TEST_BASE_H
