//
// Created by tanchao on 2022/7/12.
//

#include <cerrno>
#include <sys/epoll.h>
#include <cstring>
#include <unistd.h>
#include "dp_event.h"
#include "dp_pkt.h"
#include "dp_types.h"

#define AGENT_SUCCESS 0
#define AGENT_FAILED -1
#define RELEASED_CTX_TIMEOUT 5      // 10 second
#define RELEASED_CTX_PRUNE_FREQ 5   // 10 second
#define DP_STATS_FREQ 60            // 1 minute

extern DP_Ring dpRing;
extern dp_mnt_shm_t *g_shm;


DP_Event::DP_Event(int threadID) {
    thr_id = threadID;
    dp_running = false;
    event_fd = AGENT_FAILED;
}

DP_Event::~DP_Event() {
    Exit();
}

int DP_Event::Init() {
    event_fd = epoll_create1(EPOLL_CLOEXEC);
    if ((th_epoll_fd(thr_id) = event_fd) < 0) {
        DEBUG_INIT("failed to create epoll, thr_id=%u\n", thr_id);
        return AGENT_FAILED;
    }
    DEBUG_INIT("success to create epoll, thr_id=%u\n", thr_id);
}

void DP_Event::Exit() {
    if (dp_running) { dp_running = false; }
    if (event_fd != AGENT_FAILED) { close(event_fd); }
}

int DP_Event::AddEventNode(dp_context_t *ctx) {
    ctx->ee.events = EPOLLIN;
    ctx->ee.data.ptr = ctx;
    if (epoll_ctl(event_fd, EPOLL_CTL_ADD, ctx->fd, &ctx->ee) == -1) {
        // If the fd already in the epoll, not return error.
        if (errno != EEXIST) {
            DEBUG_ERROR(DBG_CTRL, "fail to add socket to epoll: %s\n", strerror(errno));
            return -1;
        }
    }

    ctx->epoll = true;
    return 0;
}

int DP_Event::RemoveEventNode(dp_context_t *ctx) {
    if (!ctx->epoll) {
        return 0;
    }

    if (epoll_ctl(event_fd, EPOLL_CTL_DEL, ctx->fd, &ctx->ee) == -1) {
        // Generate unnecessary error message when dp exits
        // DEBUG_ERROR(DBG_CTRL, "fail to delete socket from epoll: %s\n", strerror(errno));
        return -1;
    }

    ctx->epoll = false;
    return 0;
}

int DP_Event::GetEventFd() {
    return event_fd;
}

void DP_Event::Run() {
#define NO_WAIT    0
#define SHORT_WAIT 2
#define LONG_WAIT  1000
    // Even at packet rate of 1M pps, wait 0.002s means 2K packets. DP queue should
    // be able to accomodate it. Increase wait duration reduce idle CPU usage, but
    // worsen the latency, such as ping latency in protect mode.
    uint32_t tmo = SHORT_WAIT;
    uint32_t last_seconds = g_seconds;
    //收集 epoll 监控的事件中已经发⽣的事件
    while (dp_running) {
        // Check if polling context exist, if yes, keep polling it.
        dp_context_t *polling_ctx = th_ctx_inline(thr_id);
        if (likely(polling_ctx != NULL)) {
            if (likely(dpRing.dp_rx(polling_ctx, g_seconds) == DP_RX_MORE)) {
                tmo = NO_WAIT;
                polling_ctx = NULL;
            } else {
                if (AddEventNode(polling_ctx) < 0) {
                    tmo = SHORT_WAIT;
                    polling_ctx = NULL;
                } else {
                    tmo = LONG_WAIT;
                }
            }
        }

        int i, evs;
        evs = epoll_wait(th_epoll_fd(thr_id), epoll_evs, MAX_EPOLL_EVENTS, tmo);
        if (evs > 0) {
            for (i = 0; i < evs; i++) {
                struct epoll_event *ee = &epoll_evs[i];
                dp_context_t *ctx = (dp_context_t *) ee->data.ptr;

                if ((ee->events & EPOLLHUP) || (ee->events & EPOLLERR)) {
                    // When switch mode, port is pulled first, then epoll error happens first.
                    // ctx is more likely to be released here
                    DEBUG_ERROR(DBG_CTRL, "epoll error: %s\n", ctx->name);

                    if (ctx != polling_ctx) {
                        pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
                        if (dp_lookup_context(&th_ctx_list(thr_id), ctx->name)) {
                            dp_release_context(ctx, false);
                        }
                        pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
                    }
                } else if (ee->events & EPOLLIN) {
                    if (ctx->fd == th_ctrl_req_evfd(thr_id)) {
                        uint64_t cnt;
                        read(ctx->fd, &cnt, sizeof(uint64_t));
                        if (th_ctrl_req_evfd(thr_id)) {
                            io_ctx_t context;
                            context.tick = g_seconds;
                            context.tap = ctx->tap;
                            dpi_handle_ctrl_req(th_ctrl_req(thr_id), &context);
                        }
                    } else {
                        dpRing.dp_rx(ctx, g_seconds);
                    }
                }
            }
        }

        if (polling_ctx != NULL) {
            RemoveEventNode(polling_ctx);
        }

        if (unlikely(g_seconds - last_seconds >= 1)) {
            // Only one thread update the global variable
            if (thr_id == 0) {
                static int stats_tick = 0;
                if (++stats_tick >= STATS_INTERVAL) {
                    g_stats_slot++;
                    stats_tick = 0;
                }
            }

            static int ctx_tick = 0;
            if (++ctx_tick >= RELEASED_CTX_PRUNE_FREQ) {
                timer_queue_trim(&th_ctx_free_list(thr_id), g_seconds, dp_remove_context);
                ctx_tick = 0;
            }

            static int stats_tick = 0;
            if (++stats_tick >= DP_STATS_FREQ) {
                pthread_mutex_lock(&th_ctrl_dp_lock(thr_id));
                dp_refresh_stats(&th_ctx_list(thr_id));
                pthread_mutex_unlock(&th_ctrl_dp_lock(thr_id));
                stats_tick = 0;
            }

            dpi_timeout(g_seconds);
            // Update heartbeat
            g_shm->dp_hb[thr_id]++;
            last_seconds = g_seconds;
        }
    }

}


