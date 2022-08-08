//
// Created by Administrator on 2022/7/24.
//

#ifndef ARDP_DP_PKT_H
#define ARDP_DP_PKT_H

#include "dp_ring.h"

dp_context_t *dp_add_ctrl_req_event(int thr_id);
int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id);
dp_context_t *dp_alloc_context(const char *iface, int thr_id, bool tap, bool jumboframe, uint blocks, uint batch);
dp_context_t *dp_lookup_context(struct cds_hlist_head *list, const char *name);
void dp_refresh_stats(struct cds_hlist_head *list);
void dp_release_context(dp_context_t *ctx, bool kill);
void dp_remove_context(timer_node_t *node);
void dp_get_stats(dp_context_t *ctx);
#endif //ARDP_DP_PKT_H
