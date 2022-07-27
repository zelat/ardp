//
// Created by tanchao on 2022/7/5.
//
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <base/utils/singleton.h>

#ifdef __cplusplus
extern "C"
{
#endif
#include "base/helper.h"
#include "base/bits.h"
#include "base/rcu_map.h"
#include "base/debug.h"
#include "apis.h"
#ifdef __cplusplus
}
#endif
#include "base.h"
#include "dp_ctrl_thread.h"
#include "dp_types.h"

using namespace std;

pthread_cond_t g_ctrl_req_cond;
pthread_mutex_t g_ctrl_req_lock;
pthread_cond_t g_dlp_ctrl_req_cond;
pthread_mutex_t g_dlp_ctrl_req_lock;

io_internal_subnet4_t *g_internal_subnet4;
io_internal_subnet4_t *g_policy_addr;

io_spec_internal_subnet4_t *g_specialip_subnet4;
uint8_t g_xff_enabled = 0;

extern dp_mnt_shm_t *g_shm;
extern int g_running;
extern dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];
extern int dp_data_add_port(const char *iface, bool jumboframe, int thr_id);
extern dp_context_t *dp_add_ctrl_req_event(int thr_id);

static int conn4_match(struct cds_lfht_node *ht_node, const void *key) {
    conn_node_t *cnode = STRUCT_OF(ht_node, conn_node_t, node);
    DPMsgConnect *conn = &cnode->conn;
    const conn4_key_t *ckey = (conn4_key_t *) key;

    return (conn->PolicyId == ckey->pol_id && ip4_get(conn->ClientIP) == ckey->client &&
            ip4_get(conn->ServerIP) == ckey->server &&
            !!FLAGS_TEST(conn->Flags, DPCONN_FLAG_INGRESS) == ckey->ingress &&
            conn->Application == ckey->application && conn->ServerPort == ckey->port && conn->IPProto == ckey->ipproto)
           ? 1 : 0;
}

static uint32_t conn4_hash(const void *key) {
    const conn4_key_t *ckey = (conn4_key_t *) key;

    return sdbm_hash((uint8_t *) &ckey->client, 4) +
           sdbm_hash((uint8_t *) &ckey->server, 4) + ckey->port + ckey->ingress + ckey->pol_id;
}

//对经过dp的流量进行限速
static void dp_rate_limiter_reset(dp_rate_limter_t *rl, uint16_t dur, uint16_t dur_cnt_limit) {
    memset(rl, 0, sizeof(dp_rate_limter_t));
    rl->dur = dur;
    rl->dur_cnt_limit = dur_cnt_limit;
    rl->start = get_current_time();
}

//初始化dp线程池
int DP_CTRL_Thread::Init() {
    int thread_id, i;
    for (thread_id = 0; thread_id < g_dp_threads; thread_id++) {
        dp_thread_data_t *th_data = &g_dp_thread_data[thread_id];      //th_data每个dp线程的数据
        th_data->log_reader = MAX_LOG_ENTRIES - 1;
        for (i = 0; i < MAX_LOG_ENTRIES; i++) {
            auto *hdr = (DPMsgHdr *) th_data->log_ring[i];
            hdr->Kind = DP_KIND_THREAT_LOG;                            //操作类型DP_KIND_THREAT_LOG
            hdr->Length = htons(
                    LOG_ENTRY_SIZE);                       //发送数据包DP_KIND_THREAT_LOG的大小 = 消息头DPMsgHdr大小 + DPMsgThreatlog的大小
        }

        //connection map
        rcu_map_init(&th_data->conn4_map[0], 128, offsetof(conn_node_t, node),
                     conn4_match, conn4_hash);
        rcu_map_init(&th_data->conn4_map[1], 128, offsetof(conn_node_t, node),
                     conn4_match, conn4_hash);
        th_data->conn4_map_cnt[0] = 0;
        th_data->conn4_map_cnt[1] = 0;

        dp_rate_limiter_reset(&th_data->conn4_rl, CONNECT_RL_DUR, CONNECT_RL_CNT);
        uatomic_set(&th_data->conn4_map_cur, 0);
    }
}

int DP_CTRL_Thread::dp_ctrl_handler() {
    int size, ret = 0;
    char ctrl_msg_buf[BUF_SIZE];

    size = socketDpServer.ReceiveBinary(ctrl_msg_buf, BUF_SIZE - 1);

    ctrl_msg_buf[size] = '\0';

    json_t *root;
    json_error_t error;

    root = json_loads(ctrl_msg_buf, 0, &error);
    if (root == NULL) {
        cout << "Invalid json format on line " << error.line << ": " << error.text << endl;
        return -1;
    }

    const char *key;
    json_t *msg;

    json_object_foreach(root, key, msg) {
        //测试
        if (strcmp(key, "ctrl_keep_alive") == 0) {
            cout << json_dumps(msg, JSON_ENSURE_ASCII) << endl;
            dp_ctrl_keep_alive(msg);
            continue;
        }
        cout << json_dumps(msg, JSON_ENSURE_ASCII) << endl;
        if (strcmp(key, "ctrl_add_srvc_port") == 0) {
            ret = dp_ctrl_add_srvc_port(msg);
        } else if (strcmp(key, "ctrl_del_srvc_port") == 0) {
            cout << "dp_ctrl_del_srvc_port" << endl;
        } else if (strcmp(key, "ctrl_add_port_pair") == 0) {
            cout << "dp_ctrl_add_port_pair" << endl;
        } else if (strcmp(key, "ctrl_del_port_pair") == 0) {
            cout << "dp_ctrl_del_port_pair" << endl;
        } else if (strcmp(key, "ctrl_add_tap_port") == 0) {
            cout << "dp_ctrl_add_tap_port" << endl;
        } else if (strcmp(key, "ctrl_del_tap_port") == 0) {
            cout << "dp_ctrl_del_tap_port" << endl;
        } else if (strcmp(key, "ctrl_add_nfq_port") == 0) {
            cout << "dp_ctrl_add_nfq_port" << endl;
        } else if (strcmp(key, "ctrl_del_nfq_port") == 0) {
            cout << "dp_ctrl_del_nfq_port" << endl;
        } else if (strcmp(key, "ctrl_add_mac") == 0) {
            cout << "dp_ctrl_add_mac" << endl;
        } else if (strcmp(key, "ctrl_del_mac") == 0) {
            cout << "dp_ctrl_del_mac" << endl;
        } else if (strcmp(key, "ctrl_cfg_mac") == 0) {
            cout << "dp_ctrl_cfg_mac" << endl;
        } else if (strcmp(key, "ctrl_refresh_app") == 0) {
            cout << "dp_ctrl_refresh_app" << endl;
        } else if (strcmp(key, "ctrl_stats_macs") == 0) {
            cout << "dp_ctrl_stats_macs" << endl;
        } else if (strcmp(key, "ctrl_stats_device") == 0) {
            cout << "dp_ctrl_stats_device" << endl;
        } else if (strcmp(key, "ctrl_counter_device") == 0) {
            cout << "dp_ctrl_counter_device" << endl;
        } else if (strcmp(key, "ctrl_count_session") == 0) {
            cout << "dp_ctrl_count_session" << endl;
        } else if (strcmp(key, "ctrl_list_session") == 0) {
            cout << "dp_ctrl_list_session" << endl;
        } else if (strcmp(key, "ctrl_clear_session") == 0) {
            cout << "dp_ctrl_clear_session" << endl;
        } else if (strcmp(key, "ctrl_list_meter") == 0) {
            cout << "dp_ctrl_list_meter" << endl;
        } else if (strcmp(key, "ctrl_set_debug") == 0) {
            cout << "dp_ctrl_set_debug" << endl;
        } else if (strcmp(key, "ctrl_cfg_policy") == 0) {
            cout << "dp_ctrl_cfg_policy" << endl;
        } else if (strcmp(key, "ctrl_cfg_del_fqdn") == 0) {
            cout << "dp_ctrl_del_fqdn" << endl;
        } else if (strcmp(key, "ctrl_cfg_set_fqdn") == 0) {
            cout << "dp_ctrl_set_fqdn" << endl;
        } else if (strcmp(key, "ctrl_cfg_internal_net") == 0) {
            ret = dp_ctrl_cfg_internal_net(msg, true);
        } else if (strcmp(key, "ctrl_cfg_specip_net") == 0) {
            cout << "dp_ctrl_cfg_specialip_net" << endl;
        } else if (strcmp(key, "ctrl_cfg_policy_addr") == 0) {
            ret = dp_ctrl_cfg_internal_net(msg, false);
        } else if (strcmp(key, "ctrl_cfg_dlp") == 0) {
            cout << "dp_ctrl_cfg_dlp" << endl;
        } else if (strcmp(key, "ctrl_cfg_dlpmac") == 0) {
            cout << "dp_ctrl_del_dlp" << endl;
        } else if (strcmp(key, "ctrl_bld_dlp") == 0) {
            cout << "dp_ctrl_bld_dlp" << endl;
        } else if (strcmp(key, "ctrl_bld_dlpmac") == 0) {
            cout << "dp_ctrl_bld_dlp_update_ep" << endl;
        } else if (strcmp(key, "ctrl_sys_conf") == 0) {
            cout << "dp_ctrl_sys_conf" << endl;
        }
    }

    json_decref(root);
    return ret;
}

//dp与agent通信主函数
void DP_CTRL_Thread::dp_ctrl_loop() {
    int ret, round = 0;
    fd_set read_fds;
    struct timeval timeout;
    struct timespec last, now;

    strlcpy(THREAD_NAME, "cmd", MAX_THREAD_NAME_LEN);

    rcu_register_thread();

    unlink(DP_SERVER_SOCK);
    //创建通信句柄文件
    g_ctrl_fd = socketDpServer.Init();
    g_ctrl_notify_fd = socketCtrlNotify.Init();

    /* 互斥锁初始化. */
    pthread_mutex_init(&g_ctrl_req_lock, NULL);
    pthread_cond_init(&g_ctrl_req_cond, NULL);
    pthread_mutex_init(&g_dlp_ctrl_req_lock, NULL);
    pthread_cond_init(&g_dlp_ctrl_req_cond, NULL);

    clock_gettime(CLOCK_MONOTONIC, &last);
    while (g_running) {
        cout << "等待数据传输" << endl;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        //初始化线程组
        FD_ZERO(&read_fds);
        FD_SET(g_ctrl_fd, &read_fds);
        ret = select(g_ctrl_fd + 1, &read_fds, nullptr, nullptr, &timeout);

        if (ret > 0 && FD_ISSET(g_ctrl_fd, &read_fds)) {
            cout << "接收到agent发送的消息" << endl;
            dp_ctrl_handler();
        }

        clock_gettime(CLOCK_MONOTONIC, &now);

        if (now.tv_sec - last.tv_sec >= 2) {
            last = now;
            //发送数据给agent
            //dp_ctrl_update_app(false);
        }
        round++;
    }

    close(g_ctrl_notify_fd);
    close(g_ctrl_fd);
    unlink(DP_SERVER_SOCK);
    rcu_map_destroy(&g_ep_map);
    rcu_unregister_thread();
}

int DP_CTRL_Thread::dp_ctrl_cfg_internal_net(json_t *msg, bool internal) {
    printf("test");
    int count;
    int flag;
    json_t *sa, *c_sa;
    io_internal_subnet4_t *subnet4, *tsubnet4, *old;
    static io_internal_subnet4_t *t_internal_subnet4 = NULL;
    bool multiple_msg = false;

    flag = json_integer_value(json_object_get(msg, "flag"));
    sa = json_object_get(msg, "subnet_addr");
    count = json_array_size(sa);

    //给所有subnets分配一块连续的内存区
    subnet4 = (io_internal_subnet4_t *) calloc(sizeof(io_internal_subnet4_t) + count * sizeof(io_subnet4_t), 1);
    if (!subnet4) {
        std::cout << "Out of memory!" << std::endl;
    }

    //将agent发送过来的json数据转化成C结构
    subnet4->count = count;
    for (int i = 0; i < count; i++) {
        c_sa = json_array_get(sa, i);
        subnet4->list[i].ip = inet_addr(json_string_value(json_object_get(c_sa, "ip")));
        subnet4->list[i].mask = inet_addr(json_string_value(json_object_get(c_sa, "mask")));
    }

    if (flag & MSG_START) {
        t_internal_subnet4 = subnet4;
    } else {
        if (!t_internal_subnet4) {
            if (internal) {
                std::cout << "missed internal ip msg start!" << std::endl;
            } else {
                std::cout << "missed policy addr msg start!" << std::endl;
            }
            return -1;
        }
        tsubnet4 = (io_internal_subnet4_t *) calloc(
                sizeof(io_internal_subnet4_t) + (t_internal_subnet4->count + count) * sizeof(io_subnet4_t), 1);
        if (!tsubnet4) {
            std::cout << "out of memory!!" << std::endl;
            return -1;
        }

        memcpy(&tsubnet4->list[0], &t_internal_subnet4->list[0], sizeof(io_subnet4_t) * t_internal_subnet4->count);
        memcpy(&tsubnet4->list[t_internal_subnet4->count], &subnet4->list[0],
               sizeof(io_subnet4_t) * subnet4->count);
        tsubnet4->count = t_internal_subnet4->count + count;
        free(subnet4);
        free(t_internal_subnet4);
        t_internal_subnet4 = tsubnet4;
        multiple_msg = true;
    }


    if (!(flag & MSG_END)) {
        return 0;
    }

    if (internal) {
        old = g_internal_subnet4;
    } else {
        old = g_policy_addr;
    }
    if (multiple_msg) {
        if (internal) {
            g_internal_subnet4 = tsubnet4;
        } else {
            g_policy_addr = tsubnet4;
        }
    } else {
        if (internal) {
            g_internal_subnet4 = subnet4;
        } else {
            g_policy_addr = subnet4;
        }
    }

    synchronize_rcu();

    free(old);

    return 0;
}

int DP_CTRL_Thread::dp_ctrl_keep_alive(json_t *msg) {
    uint32_t seq_num = json_integer_value(json_object_get(msg, "seq_num"));
    uint8_t buf[sizeof(DPMsgHdr) + sizeof(uint32_t)];

    DPMsgHdr *hdr = (DPMsgHdr *) buf;
    hdr->Kind = DP_KIND_KEEP_ALIVE;
    hdr->Length = htons(sizeof(DPMsgHdr) + sizeof(uint32_t));
    hdr->More = 0;

    uint32_t *m = (uint32_t *) (buf + sizeof(DPMsgHdr));
    *m = htonl(seq_num);

    socketDpServer.SendBinary(buf, sizeof(buf));
    return 0;
}

//增加一个serivce port
int DP_CTRL_Thread::dp_ctrl_add_srvc_port(json_t *msg) {
    const char *iface;
    json_t *jumboframe_obj;
    bool jumboframe = false;

    jumboframe_obj = json_object_get(msg, "jumboframe");
    if (jumboframe_obj != NULL) {
        jumboframe = json_boolean_value(jumboframe_obj);
    }

    iface = json_string_value(json_object_get(msg, "iface"));
    printf("iface=%s, jumboframe=%d\n", iface, jumboframe);

    return dp_data_add_port(iface, jumboframe, 0);
}

void *DP_CTRL_Thread::dp_bld_dlp_thr(void *args) {
    return nullptr;
}

void *DP_CTRL_Thread::dp_data_thr(void *args) {
    struct epoll_event epoll_evs[MAX_EPOLL_EVENTS];
    uint32_t tmo;
    int thr_id = *(int *)args;
    dp_context_t *ctrl_req_ev_ctx;

    thr_id = thr_id % MAX_DP_THREADS;

    THREAD_ID = thr_id;
    snprintf(THREAD_NAME, MAX_THREAD_NAME_LEN, "dp%u", thr_id);

    // Create epoll, add ctrl_req event
    if ((g_dp_thread_data[thr_id].epoll_fd = epoll_create(MAX_EPOLL_EVENTS)) < 0) {
        DEBUG_INIT("failed to create epoll, thr_id=%u\n", thr_id);
        return NULL;
    }
    DEBUG_INIT("success to create epoll, thr_id=%u\n", thr_id);
    ctrl_req_ev_ctx = dp_add_ctrl_req_event(thr_id);
    if (ctrl_req_ev_ctx == NULL) {
        return NULL;
    }

    rcu_register_thread();
//
//    g_shm->dp_active[thr_id] = true;
//    pthread_mutex_init(&g_dp_thread_data[thr_id].ctrl_dp_lock, NULL);
//    CDS_INIT_HLIST_HEAD(&g_dp_thread_data[thr_id].ctx_list);
//    timer_queue_init(&g_dp_thread_data[thr_id].ctx_free_list, RELEASED_CTX_TIMEOUT);
//
//    //初始化每个线程
//    dpi_init(DPI_INIT);
//
//    DEBUG_INIT("dp thread starts\n");
    return nullptr;
}




