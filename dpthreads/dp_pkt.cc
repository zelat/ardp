//
// Created by tanchao on 2022/7/14.
//

#include <base/config/config.h>

#ifdef __cplusplus
extern "C"
{
#endif
#include "base/helper.h"
#ifdef __cplusplus
}
#endif

#include "dp_ctrl_thread.h"
#include "dp_types.h"
#include "urcu/hlist.h"
#include "dp_ring.h"

#define INLINE_BLOCK 2048
#define INLINE_BATCH 4096
#define TAP_BLOCK 512
#define TAP_BATCH 256
#define INLINE_BLOCK_NOTC 512
#define INLINE_BATCH_NOTC 1024
#define NFQ_BLOCK 128                                         //max q length
#define NFQ_BATCH 128

dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];

#define th_epoll_fd(thr_id)      (g_dp_thread_data[thr_id].epoll_fd)
#define th_ctx_list(thr_id)      (g_dp_thread_data[thr_id].ctx_list)
#define th_ctx_free_list(thr_id) (g_dp_thread_data[thr_id].ctx_free_list)
#define th_ctx_inline(thr_id)    (g_dp_thread_data[thr_id].ctx_inline)
#define th_ctrl_dp_lock(thr_id)  (g_dp_thread_data[thr_id].ctrl_dp_lock)
#define th_ctrl_req_evfd(thr_id) (g_dp_thread_data[thr_id].ctrl_req_evfd)
#define th_ctrl_req(thr_id)      (g_dp_thread_data[thr_id].ctrl_req)

//    int dp_open_socket(dp_context_t *ctx, const char *iface, bool tap, bool tc, uint blocks, uint batch);
DP_Ring dpRing;

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

int dp_data_add_port(const char *iface, bool jumboframe, int thr_id) {
    int ret = 0;
    dp_context_t *ctx;

    thr_id = thr_id % MAX_DP_THREADS;
    if (th_epoll_fd(thr_id) == 0) {
        // TODO: May need to wait a while for dp thread ready
        printf("epoll is not initiated, iface=%s thr_id=%d\n", iface, thr_id);
        return -1;
    }

    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
    do {
        if (th_ctx_inline(thr_id) != nullptr) {
            printf("iface already exists, iface=%s\n", iface);
            break;
        }
        ctx = dp_alloc_context(iface, thr_id, false, jumboframe, INLINE_BLOCK, INLINE_BATCH);
        if (ctx == NULL) {
            ret = -1;
            break;
        }
        ctx->peer_ctx = ctx;
        th_ctx_inline(thr_id) = (dp_context_ *) ctx;

        strlcpy(ctx->name, iface, sizeof(ctx->name));
        cds_hlist_add_head(&ctx->link, &th_ctx_list(thr_id));

        printf("added iface=%s fd=%d\n", iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
    return ret;
}