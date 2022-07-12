//
// Created by Administrator on 2022/7/5.
//

#ifndef ARDP_DP_CTRL_THREAD_H
#define ARDP_DP_CTRL_THREAD_H

#include <ctime>
#include <base/utils/singleton.h>
#include "base.h"
#include "base/config/config.h"
#include "domain_socket_ctrl_dp.h"

namespace dpthreads{
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

class DP_CTRL_Thread{
    private:
        int g_dp_threads;                                       //agent与DP连接的线程数
        dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];      //线程池
        int g_ctrl_fd;
        int g_ctrl_notify_fd;
        int g_running;
        uint8_t g_notify_msg[DP_MSG_SIZE];
        dpi_fqdn_hdl_t *g_fqdn_hdl;
        rcu_map_t g_ep_map;
        static int conn4_match(struct cds_lfht_node *ht_node, const void *key);
        static uint32_t conn4_hash(const void *key);
        int dp_ctrl_send_binary(void *data, int len);
        int dp_ctrl_handler(int fd);
        int dp_ctrl_notify_ctrl(void *data, int len);
    public:
        DP_CTRL_Thread();
        int Init();
        void Exit();
        void dp_rate_limiter_reset(dp_rate_limter_t *rl, uint16_t dur, uint16_t dur_cnt_limit);
        int dp_ctrl_keep_alive(json_t *msg);
        void dp_ctrl_update_app(bool refresh);
        void dp_ctrl_loop();
    private:
        DomainSocketDPServer socketDpServer;
    };
}

#endif //ARDP_DP_CTRL_THREAD_H
