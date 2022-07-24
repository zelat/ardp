//
// Created by tanchao on 2022/7/14.
//

#include <base/config/config.h>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>
#include "urcu.h"
#include "urcu/rcuhlist.h"

#ifdef __cplusplus
extern "C"
{
#endif
#include "base/helper.h"
#include "base/debug.h"
#ifdef __cplusplus
}
#endif

#include "urcu/hlist.h"
#include "dp_ctrl_thread.h"
#include "dp_pkt.h"
#include "dp_types.h"
#include "dp_ring.h"
#include "apis.h"
#include "base.h"

extern dp_mnt_shm_t *g_shm;

#define INLINE_BLOCK 2048
#define INLINE_BATCH 4096
#define TAP_BLOCK 512
#define TAP_BATCH 256
#define INLINE_BLOCK_NOTC 512
#define INLINE_BATCH_NOTC 1024
#define NFQ_BLOCK 128//max q length
#define NFQ_BATCH 128
// For a context in free list, usually it can be release when all packets in the queue
// are processed, but there are cases that sessions send out RST after idling some
// time, ctx_inline is used in that case, so we can recycle pretty quickly.
#define RELEASED_CTX_TIMEOUT 5      // 10 second
#define RELEASED_CTX_PRUNE_FREQ 5   // 10 second
#define DP_STATS_FREQ 60            // 1 minute
#define MAX_EPOLL_EVENTS 128

int bld_dlp_epoll_fd;
int bld_dlp_ctrl_req_evfd;
uint32_t bld_dlp_ctrl_req;
dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];

int dp_open_socket(dp_context_t *ctx, const char *iface, bool tap, bool tc, uint blocks, uint batch);

int dp_rx(dp_context_t *ctx, uint32_t tick);

void dp_get_stats(dp_context_t *ctx);

int dp_open_nfq_handle(dp_context_t *ctx, bool jumboframe, uint blocks, uint batch);

DP_Ring dpRing;

static const char *get_tap_name(char *name, const char *netns, const char *iface) {
    snprintf(name, CTX_NAME_LEN, "%s-%s", netns, iface);
    return name;
}

static int enter_netns(const char *netns) {
    int curfd, netfd;

    if ((curfd = open("/proc/self/ns/net", O_RDONLY)) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to open current network namespace\n");
        return -1;
    }
    if ((netfd = open(netns, O_RDONLY)) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to open network namespace: netns=%s\n", netns);
        close(curfd);
        return -1;
    }
    if (setns(netfd, CLONE_NEWNET) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to enter network namespace: netns=%s error=%s\n", netns, strerror(errno));
        close(netfd);
        close(curfd);
        return -1;
    }
    close(netfd);
    return curfd;
}

static int restore_netns(int fd) {
    if (setns(fd, CLONE_NEWNET) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to restore network namespace: error=%s\n", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static dp_context_t *
dp_alloc_context(const char *iface, int thr_id, bool tap, bool jumboframe, uint blocks, uint batch) {
    int fd;
    dp_context_t *ctx;
    ctx = (dp_context_t *) calloc(1, sizeof(*ctx));
    if (ctx == nullptr) {
        return nullptr;
    }

    fd = dpRing.dp_open_socket(ctx, iface, tap, jumboframe, blocks, batch);
    if (fd < 0) {
        printf("fail to open dp socket, iface=%s\n", iface);
        free(ctx);
        return nullptr;
    }

    ctx->thr_id = thr_id;
    ctx->fd = fd;
    ctx->tap = tap;
    ctx->tc = true;
    ctx->jumboframe = jumboframe;
    ctx->nfq = false;

    printf("ctx=%p\n", ctx);

    return ctx;
}

static dp_context_t *dp_lookup_context(struct cds_hlist_head *list, const char *name) {
    dp_context_t *ctx;
    struct cds_hlist_node *itr;

    cds_hlist_for_each_entry_rcu(ctx, itr, list, link) {
        if (strcmp(ctx->name, name) == 0) {
            return ctx;
        }
    }

    return NULL;
}

static int dp_epoll_add_ctx(dp_context_t *ctx, int thr_id)
{
    ctx->ee.events = EPOLLIN;
    ctx->ee.data.ptr = ctx;
    if (epoll_ctl(g_dp_thread_data[thr_id].epoll_fd, EPOLL_CTL_ADD, ctx->fd, &ctx->ee) == -1) {
        // If the fd already in the epoll, not return error.
        if (errno != EEXIST) {
            DEBUG_ERROR(DBG_CTRL, "fail to add socket to epoll: %s\n", strerror(errno));
            return -1;
        }
    }

    ctx->epoll = true;
    return 0;
}

/* This function can only be called by dp_dlp_wait_ctrl_req_thr() */
static int dp_ctrl_wait_dlp_threads() {
    int rc = 0;

    while (1) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += CTRL_DLP_REQ_TIMEOUT;

        rc = pthread_cond_timedwait(&g_dlp_ctrl_req_cond, &g_dlp_ctrl_req_lock, &ts);
        if (rc == 0) {
            break;
        }
        if (rc == ETIMEDOUT) {
            DEBUG_CTRL("timeout: wait dlp thread\n");
            break;
        }
    }

    return rc;
}

int dp_data_add_port(const char *iface, bool jumboframe, int thr_id) {
    int ret = 0;
    dp_context_t *ctx;

    printf("thr_id = %d", thr_id);
    thr_id = thr_id % MAX_DP_THREADS;
    if (g_dp_thread_data[thr_id].epoll_fd == 0) {
        // TODO: May need to wait a while for dp thread ready
        printf("epoll is not initiated, iface=%s thr_id=%d\n", iface, thr_id);
        return -1;
    }

    //该线程已被锁定
    pthread_mutex_lock(&g_dp_thread_data[thr_id].ctrl_dp_lock);

    do {
        printf("testing===================");
        if (g_dp_thread_data[thr_id].ctx_inline != nullptr) {
            printf("iface already exists, iface=%s\n", iface);
            break;
        }
        ctx = dp_alloc_context(iface, thr_id, false, jumboframe, INLINE_BLOCK, INLINE_BATCH);
        if (ctx == NULL) {
            ret = -1;
            break;
        }
        ctx->peer_ctx = ctx;
        g_dp_thread_data[thr_id].ctx_inline = ctx;

        strlcpy(ctx->name, iface, sizeof(ctx->name));
        cds_hlist_add_head(&ctx->link, &g_dp_thread_data[thr_id].ctx_list);

        printf("added iface=%s fd=%d\n", iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&g_dp_thread_data[thr_id].ctrl_dp_lock);
    return ret;
}

int dp_dlp_wait_ctrl_req_thr(int req) {
    uint64_t w = 1;
    ssize_t s;
    int rc = 0;

    DEBUG_CTRL("dlp req=%d\n", req);

    pthread_mutex_lock(&g_dlp_ctrl_req_lock);
    bld_dlp_ctrl_req = req;
    s = write(bld_dlp_ctrl_req_evfd, &w, sizeof(uint64_t));
    if (s != sizeof(uint64_t)) {
        pthread_mutex_unlock(&g_dlp_ctrl_req_lock);
        return -1;
    }
    rc = dp_ctrl_wait_dlp_threads();
    bld_dlp_ctrl_req = 0;
    pthread_mutex_unlock(&g_dlp_ctrl_req_lock);
    return rc;
}

int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id) {
    int ret = 0;
    dp_context_t *ctx;

    thr_id = thr_id % MAX_DP_THREADS;

    if (g_dp_thread_data[thr_id].epoll_fd == 0) {
        // TODO: May need to wait a while for dp thread ready
        DEBUG_ERROR(DBG_CTRL, "epoll is not initiated, netns=%s thr_id=%d\n", netns, thr_id);
        return -1;
    }

    int curns_fd;
    if ((curns_fd = enter_netns(netns)) < 0) {
        return -1;
    }

    pthread_mutex_lock(&g_dp_thread_data[thr_id].ctrl_dp_lock);

    do {
        char name[CTX_NAME_LEN];
        get_tap_name(name, netns, iface);
        ctx = dp_lookup_context(&g_dp_thread_data[thr_id].ctx_list, name);
        if (ctx != NULL) {
            // handle mac address change
            ether_aton_r(ep_mac, &ctx->ep_mac);
            DEBUG_CTRL("tap already exists, netns=%s iface=%s\n", netns, iface);
            break;
        }

        ctx = dp_alloc_context(iface, thr_id, true, false, TAP_BLOCK, TAP_BATCH);
        if (ctx == NULL) {
            ret = -1;
            break;
        }
        ctx->peer_ctx = ctx;

        if (dp_epoll_add_ctx(ctx, thr_id) < 0) {
            dpRing.dp_close_socket(ctx);
            free(ctx);
            ret = -1;
            break;
        }

        ether_aton_r(ep_mac, &ctx->ep_mac);
        strlcpy(ctx->name, name, sizeof(ctx->name));
        cds_hlist_add_head_rcu(&ctx->link, &g_dp_thread_data[thr_id].ctx_list);

        DEBUG_CTRL("tap added netns=%s iface=%s fd=%d\n", netns, iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&g_dp_thread_data[thr_id].ctrl_dp_lock);

    restore_netns(curns_fd);

    return ret;
}