//
// Created by tancho on 2022/7/15.
//

#ifndef ARDP_DP_TYPES_H
#define ARDP_DP_TYPES_H

#include <sys/epoll.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include "urcu/hlist.h"
#include "base/config/config.h"
#include "urcu/rculfhash.h"
#include "defs.h"
#include "dpi/dpi_entry.h"
#ifdef __cplusplus
extern "C"
{
#endif
#include "base/rcu_map.h"
#include "base/timer_queue.h"
#include "base/debug.h"
#ifdef __cplusplus
}
#endif

#define DP_RX_DONE 0
#define DP_RX_MORE -1

typedef struct rate_limiter_ {
    uint16_t dur;             // in second
    uint16_t dur_cnt_limit;
    uint32_t start;
    uint32_t cnt;
    uint32_t total_drop;
    uint32_t total_pass;
} dp_rate_limter_t;

extern int g_stats_slot;

typedef struct dp_mnt_shm_ {
    uint32_t dp_hb[MAX_DP_THREADS];
    bool dp_active[MAX_DP_THREADS];
} dp_mnt_shm_t;

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

//connection map
typedef struct conn_node_ {
    struct cds_lfht_node node;
    DPMsgConnect conn;
} conn_node_t;

typedef struct conn4_key_ {
    uint32_t pol_id;
    uint32_t client, server;
    uint16_t port;
    uint16_t application;
    uint8_t ipproto;
    bool ingress;
} conn4_key_t;

typedef struct dp_stats_ {
    uint64_t rx;
    uint64_t rx_drops;
    uint64_t tx_drops;
    uint64_t tx;
} dp_stats_t;

typedef struct dp_ring_ {
    uint8_t *rx_map;
    uint8_t *tx_map;
    uint32_t rx_offset;
    uint32_t tx_offset;
    union {
        struct tpacket_req req;
        struct tpacket_req3 req3;
    };
    uint32_t size;
    uint32_t map_size;
    uint32_t batch;

    int (*rx)(struct dp_context_ *ctx, uint32_t tick);

    int (*tx)(struct dp_context_ *ctx, uint8_t *pkt, int len, bool large_frame);

    void (*stats)(int fd, dp_stats_t *stats);
} dp_ring_t;

typedef struct dp_nfq_ {
    struct nfq_handle *nfq_hdl;
    struct nfq_q_handle *nfq_q_hdl;
    uint32_t blocks;//max queue length
    uint32_t batch;
    uint32_t last_tick;
    uint8_t rx_accept;
    uint8_t rx_deny;

    int (*rx)(struct dp_context_ *ctx, uint32_t tick);

    void (*stats)(struct dp_context_ *ctx);
} dp_nfq_t;

typedef struct dp_context_ {
    struct cds_hlist_node link;
    timer_node_t free_node;

    struct epoll_event ee;
    int fd;
#define CTX_NAME_LEN 64 // must be > IFACE_NAME_LEN=16 and "/proc/%d/ns/net"
#define CTX_NFQ_PREFIX "nfq"
    char name[CTX_NAME_LEN];
    dp_ring_t ring;
    dp_nfq_t nfq_ctx;
    dp_stats_t stats;
    struct ether_addr ep_mac;
#define DEFAULT_PENDING_LIMIT 16
    uint8_t tx_pending;
    uint8_t thr_id: 4,
            released: 1;
    bool tap;
    bool tc;
    bool jumboframe;
    bool nfq;
    bool epoll;
    struct dp_context_ *peer_ctx; // for vbr peer is self, for no-tc vin/vex pair with each other.
} dp_context_t;

extern dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];

#endif //ARDP_DP_TYPES_H
