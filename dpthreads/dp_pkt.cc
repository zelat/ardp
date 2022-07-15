//
// Created by tanchao on 2022/7/14.
//

#include <base/config/config.h>
#include "dp_ctrl_thread.h"

namespace dpthreads {

    dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];

    #define th_epoll_fd(thr_id)      (g_dp_thread_data[thr_id].epoll_fd)
    #define th_ctx_list(thr_id)      (g_dp_thread_data[thr_id].ctx_list)
    #define th_ctx_free_list(thr_id) (g_dp_thread_data[thr_id].ctx_free_list)
    #define th_ctx_inline(thr_id)    (g_dp_thread_data[thr_id].ctx_inline)
    #define th_ctrl_dp_lock(thr_id)  (g_dp_thread_data[thr_id].ctrl_dp_lock)
    #define th_ctrl_req_evfd(thr_id) (g_dp_thread_data[thr_id].ctrl_req_evfd)
    #define th_ctrl_req(thr_id)      (g_dp_thread_data[thr_id].ctrl_req)

    int ardp_add_port(const char * iface, bool jumboframe, int thr_id){
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
            if (th_ctx_inline(thr_id) != nullptr){
                printf("iface already exists, iface=%s\n", iface);
                break;
            }
            ctx = dp_alloc_context(iface, thr_id, false, jumboframe, INLINE_BLOCK, INLINE_BATCH);
        } while (false);
    }
}