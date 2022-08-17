//
// Created by tanchao on 2022/7/14.
//

#include <base/config/config.h>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/eventfd.h>
#include "urcu.h"
#include "urcu/rcuhlist.h"
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#ifdef __cplusplus
extern "C"
{
#endif
#include "base/helper.h"
#include "base/debug.h"
#ifdef __cplusplus
}
#endif
#include "dp_ctrl_thread.h"
#include "dp_pkt.h"
#include "dp_event.h"

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

DP_Ring dpRing;
int bld_dlp_epoll_fd;
int bld_dlp_ctrl_req_evfd;
uint32_t bld_dlp_ctrl_req;
//int dp_open_socket(dp_context_t *ctx, const char *iface, bool tap, bool tc, uint blocks, uint batch);
//
//int dp_rx(dp_context_t *ctx, uint32_t tick);
//
//void dp_get_stats(dp_context_t *ctx);
//
//int dp_open_nfq_handle(dp_context_t *ctx, bool jumboframe, uint blocks, uint batch);

static const char *get_tap_name(char *name, const char *netns, const char *iface) {
    snprintf(name, CTX_NAME_LEN, "%s-%s", netns, iface);
    return name;
}

static int enter_netns(const char *netns) {
    int curfd, netfd;
    //打开当前网络命名空间
    if ((curfd = open("/proc/self/ns/net", O_RDONLY)) == -1) {
        DEBUG_ERROR(DBG_CTRL, "failed to open current network namespace\n");
        return -1;
    }
    //打开
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

static int dp_epoll_remove_ctx(dp_context_t *ctx)
{
    if (!ctx->epoll) {
        return 0;
    }

    if (epoll_ctl(th_epoll_fd(ctx->thr_id), EPOLL_CTL_DEL, ctx->fd, &ctx->ee) == -1) {
        // Generate unnecessary error message when dp exits
        // DEBUG_ERROR(DBG_CTRL, "fail to delete socket from epoll: %s\n", strerror(errno));
        return -1;
    }

    ctx->epoll = false;
    return 0;
}

static int dp_epoll_add_ctx(dp_context_t *ctx, int thr_id)
{
    ctx->ee.events = EPOLLIN;
    ctx->ee.data.ptr = ctx;
    if (epoll_ctl(th_epoll_fd(thr_id), EPOLL_CTL_ADD, ctx->fd, &ctx->ee) == -1) {
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
int dp_ctrl_wait_dlp_threads() {
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

//创建一个用于通信的fd文件
dp_context_t *dp_add_ctrl_req_event(int thr_id)
{
    int fd;
    dp_context_t *ctx;

    DEBUG_FUNC_ENTRY(DBG_CTRL);

    ctx = (dp_context_t *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }
    //创建一个eventfd对象，返回一个文件描述符
    fd = eventfd(0, 0);
    if (fd < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail to create dp_ctrl_req event fd.\n");
        free(ctx);
        return NULL;
    }

    //fcntl设置为非阻塞模式
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    ctx->thr_id = thr_id;
    ctx->fd = fd;

    ctx->ee.events = EPOLLIN;
    ctx->ee.data.ptr = ctx;

    if (epoll_ctl(th_epoll_fd(thr_id) , EPOLL_CTL_ADD, ctx->fd, &ctx->ee) == -1) {
        DEBUG_ERROR(DBG_CTRL, "fail to add socket to epoll: %s\n", strerror(errno));
        close(fd);
        free(ctx);
        return NULL;
    }

    th_ctrl_req_evfd(thr_id) = fd;

    return ctx;
}


int dp_data_add_port(const char *iface, bool jumboframe, int thr_id) {
    int ret = 0;
    dp_context_t *ctx;

    thr_id = thr_id % MAX_DP_THREADS;
    DEBUG_LOGGER("thr_id = %d\n", thr_id);
    if (th_epoll_fd(thr_id) == 0) {
        // TODO: May need to wait a while for dp thread ready
        DEBUG_ERROR(DBG_CTRL, "epoll is not initiated, iface=%s thr_id=%d\n", iface, thr_id);
        return -1;
    }

    //该线程已被锁定
    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));

    do {
        if (th_ctx_inline(thr_id) != nullptr) {
            DEBUG_CTRL("iface already exists, iface=%s\n", iface);
            break;
        }
        ctx = dp_alloc_context(iface, thr_id, false, jumboframe, INLINE_BLOCK, INLINE_BATCH);
        if (ctx == NULL) {
            ret = -1;
            break;
        }
        ctx->peer_ctx = ctx;
        th_ctx_inline(thr_id) = ctx;

        strlcpy(ctx->name, iface, sizeof(ctx->name));
        cds_hlist_add_head(&ctx->link, &th_ctx_list(thr_id));

        DEBUG_CTRL("added iface=%s fd=%d\n", iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
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

    if (th_epoll_fd(thr_id)  == 0) {
        // TODO: May need to wait a while for dp thread ready
        DEBUG_ERROR(DBG_CTRL, "epoll is not initiated, netns=%s thr_id=%d\n", netns, thr_id);
        return -1;
    }

    int curns_fd;
    if ((curns_fd = enter_netns(netns)) < 0) {
        return -1;
    }
    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
    do {
        char name[CTX_NAME_LEN];
        get_tap_name(name, netns, iface);
        ctx = dp_lookup_context(&th_ctx_list(thr_id), name);
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
        /* 进程退出 tap0不消失 如果想删除则设置为0 */
//        if(ioctl(ctx->fd, TUNSETPERSIST, 1) < 0){
//            perror("enabling TUNSETPERSIST");
//            exit(1);
//        }
        cds_hlist_add_head_rcu(&ctx->link, &th_ctx_list(thr_id));

        DEBUG_CTRL("tap added netns=%s iface=%s fd=%d\n", netns, iface, ctx->fd);
    } while (false);

    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    restore_netns(curns_fd);

    return ret;
}

dp_context_t *dp_lookup_context(struct cds_hlist_head *list, const char *name) {
    dp_context_t *ctx;
    struct cds_hlist_node *itr;

    cds_hlist_for_each_entry_rcu(ctx, itr, list, link) {
        if (strcmp(ctx->name, name) == 0) {
            return ctx;
        }
    }

    return NULL;
}

dp_context_t *dp_alloc_context(const char *iface, int thr_id, bool tap, bool jumboframe, uint blocks, uint batch) {
    int fd;
    dp_context_t *ctx;
    // 给ctx分配内存空间
    ctx = (dp_context_t *) calloc(1, sizeof(*ctx));
    if (ctx == nullptr) {
        return nullptr;
    }
    // 接收和发送以太网数据帧
    fd = dpRing.dp_open_socket(ctx, iface, tap, jumboframe, blocks, batch);
    if (fd < 0) {
        DEBUG_ERROR(DBG_CTRL, "fail to open dp socket, iface=%s\n", iface);
        free(ctx);
        return nullptr;
    }

    ctx->thr_id = thr_id;
    ctx->fd = fd;
    ctx->tap = tap;
    ctx->tc = true;
    ctx->jumboframe = jumboframe;
    ctx->nfq = false;

    return ctx;
}

void dp_refresh_stats(struct cds_hlist_head *list)
{
    dp_context_t *ctx;
    struct cds_hlist_node *itr;

    cds_hlist_for_each_entry_rcu(ctx, itr, list, link) {
        dp_get_stats(ctx);
    }
}

// Not to release socket memory if 'kill' is false
void dp_release_context(dp_context_t *ctx, bool kill)
{
    DEBUG_CTRL("ctx=%s fd=%d\n", ctx->name, ctx->fd);

    cds_hlist_del(&ctx->link);
    dp_epoll_remove_ctx(ctx);

    if (kill) {
        dpRing.dp_close_socket(ctx);
        free(ctx);
    } else {
        DEBUG_CTRL("add context to free list, ctx=%s, ts=%u\n", ctx->name, g_seconds);
        timer_queue_append(&th_ctx_free_list(ctx->thr_id), &ctx->free_node, g_seconds);
        ctx->released = 1;
    }
}

void dp_remove_context(timer_node_t *node)
{
    dp_context_t *ctx = STRUCT_OF(node, dp_context_t, free_node);
    DEBUG_CTRL("ctx=%s\n", ctx->name);
    dpRing.dp_close_socket(ctx);
    free(ctx);
}

void dp_get_stats(dp_context_t *ctx)
{
    if (ctx->nfq) {
        ctx->nfq_ctx.stats(ctx);
    } else {
        ctx->ring.stats(ctx->fd, &ctx->stats);
    }
}


void *dp_data_thr(void *args) {
    struct epoll_event epoll_evs[MAX_EPOLL_EVENTS];
    uint32_t tmo;
    int thr_id = *(int *)args;
    dp_context_t *ctrl_req_ev_ctx;

    thr_id = thr_id % MAX_DP_THREADS;
    THREAD_ID = thr_id;
    snprintf(THREAD_NAME, MAX_THREAD_NAME_LEN, "dp%u", thr_id);
    // Create epoll, add ctrl_req event
    DP_Event dpEvent(thr_id);
    if (dpEvent.Init() < 0){
        DEBUG_INIT("Failed to create epoll, thr_id=%u\n", thr_id);
    } else {
        DEBUG_INIT("Sucess to create epoll, %u\n", thr_id);
    }
    //创建一个用于通信的fd文件
    ctrl_req_ev_ctx = dp_add_ctrl_req_event(thr_id);
    if (ctrl_req_ev_ctx == NULL) {
        return NULL;
    }
    rcu_register_thread();

    g_shm->dp_active[thr_id] = true;

    pthread_mutex_init(&th_ctrl_dp_lock(thr_id), NULL);
    CDS_INIT_HLIST_HEAD(&th_ctx_list(thr_id));
    timer_queue_init(&th_ctx_free_list(thr_id), RELEASED_CTX_TIMEOUT);
    //初始化每个线程
    dpi_init(DPI_INIT);
    //事件监听
    dpEvent.Run();

    dpEvent.ReleaseFd();

    DEBUG_INIT("dp thread exits\n");

    struct cds_hlist_node *itr, *next;
    dp_context_t *ctx;
    pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
    cds_hlist_for_each_entry_safe(ctx, itr, next, &th_ctx_list(thr_id), link) {
        dp_release_context(ctx, true);
    }
    pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));

    close(ctrl_req_ev_ctx->fd);
    free(ctrl_req_ev_ctx);

    rcu_unregister_thread();

    return NULL;
}

/* 修正时间误差 */
void *debug_timer_thr(void *args) {
    snprintf(THREAD_NAME, MAX_THREAD_NAME_LEN, "tmr");
    g_start_time = time(NULL);
    while (g_running) {
        sleep(1);
        g_seconds ++;
        // 每隔30S纪录一次时间
        if ((g_seconds & 0x1f) == 0) {
            time_t time_elapsed = time(NULL) - g_start_time;
            time_t curTime = time(NULL);
            printf("CurrentTime is %s", ctime(&curTime));
            printf("Starttime is %s", ctime(&g_start_time));
            //修正时间误差
            if (time_elapsed > g_seconds) {
                DEBUG_TIMER("Advance timer for %us\n", time_elapsed - g_seconds);
                g_seconds = time_elapsed;
            }
        }
    }
    return NULL;
}