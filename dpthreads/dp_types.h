//
// Created by tancho on 2022/7/15.
//

#ifndef ARDP_DP_TYPES_H
#define ARDP_DP_TYPES_H

#include <sys/epoll.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include "urcu/hlist.h"
#ifdef __cplusplus
extern "C"
{
#endif
#include "base/timer_queue.h"
#ifdef __cplusplus
}
#endif

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

#endif //ARDP_DP_TYPES_H
