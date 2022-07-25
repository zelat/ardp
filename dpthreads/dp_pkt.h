//
// Created by Administrator on 2022/7/24.
//

#ifndef ARDP_DP_PKT_H
#define ARDP_DP_PKT_H

#include "dp_types.h"

void dp_close_socket(dp_context_t *ctx);
dp_context_t *dp_add_ctrl_req_event(int thr_id);
int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id);
#endif //ARDP_DP_PKT_H
