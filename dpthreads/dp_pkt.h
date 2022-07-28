//
// Created by Administrator on 2022/7/24.
//

#ifndef ARDP_DP_PKT_H
#define ARDP_DP_PKT_H

#include "dp_types.h"
#include "dp_ring.h"

//extern dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];

#define th_epoll_fd(thr_id)      (g_dp_thread_data[thr_id].epoll_fd)
#define th_ctx_list(thr_id)      (g_dp_thread_data[thr_id].ctx_list)
#define th_ctx_free_list(thr_id) (g_dp_thread_data[thr_id].ctx_free_list)
#define th_ctx_inline(thr_id)    (g_dp_thread_data[thr_id].ctx_inline)
#define th_ctrl_dp_lock(thr_id)  (g_dp_thread_data[thr_id].ctrl_dp_lock)
#define th_ctrl_req_evfd(thr_id) (g_dp_thread_data[thr_id].ctrl_req_evfd)
#define th_ctrl_req(thr_id)      (g_dp_thread_data[thr_id].ctrl_req)

dp_context_t *dp_add_ctrl_req_event(int thr_id);
int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id);
dp_context_t *dp_alloc_context(const char *iface, int thr_id, bool tap, bool jumboframe, uint blocks, uint batch);
dp_context_t *dp_lookup_context(struct cds_hlist_head *list, const char *name);
void dp_refresh_stats(struct cds_hlist_head *list);
void dp_release_context(dp_context_t *ctx, bool kill);
void dp_remove_context(timer_node_t *node);
void dp_get_stats(dp_context_t *ctx);
#endif //ARDP_DP_PKT_H
