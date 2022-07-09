//
// Created by tanchao on 2022/7/5.
//
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>

#ifdef __cplusplus
extern "C"
{
#endif
#include "utils/helper.h"
#include "utils/bits.h"
#include "utils/rcu_map.h"
#include "utils/debug.h"
#ifdef __cplusplus
}
#endif
#include "apis.h"
#include "ctrl.h"

using namespace std;

struct sockaddr_un ctrl::g_ctrl_notify_addr;
struct sockaddr_un ctrl::g_client_addr;

//创建socket句柄文件
int ctrl::make_named_socket(const char *filename) {
    struct sockaddr_un name;
    int sock;
    size_t size;

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    name.sun_family = AF_UNIX;
    strlcpy(name.sun_path, filename, sizeof(name.sun_path));

    size = (offsetof(struct sockaddr_un, sun_path) + strlen(name.sun_path));

    if (bind(sock, (struct sockaddr *) &name, size) < 0) {
        return -1;
    }

    return sock;
}

int ctrl::make_notify_client(const char *filename) {
    int sock;

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    g_ctrl_notify_addr.sun_family = AF_UNIX;
    strlcpy(g_ctrl_notify_addr.sun_path, filename, sizeof(g_ctrl_notify_addr.sun_path));

    return sock;
}

int ctrl::conn4_match(struct cds_lfht_node *ht_node, const void *key) {
    conn_node_t *cnode = STRUCT_OF(ht_node, conn_node_t, node);
    DPMsgConnect *conn = &cnode->conn;
    const conn4_key_t *ckey = (conn4_key_t *)key;

    return (conn->PolicyId == ckey->pol_id && ip4_get(conn->ClientIP) == ckey->client &&
            ip4_get(conn->ServerIP) == ckey->server && !!FLAGS_TEST(conn->Flags, DPCONN_FLAG_INGRESS) == ckey->ingress &&
            conn->Application == ckey->application && conn->ServerPort == ckey->port && conn->IPProto == ckey->ipproto) ? 1 : 0;
}

uint32_t ctrl::conn4_hash(const void *key) {
    const conn4_key_t *ckey = (conn4_key_t *)key;

    return sdbm_hash((uint8_t *)&ckey->client, 4) +
           sdbm_hash((uint8_t *)&ckey->server, 4) + ckey->port + ckey->ingress + ckey->pol_id;
}

//对经过dp的流量进行限速
void ctrl::dp_rate_limiter_reset(dp_rate_limter_t *rl, uint16_t dur, uint16_t dur_cnt_limit){
    memset(rl, 0, sizeof(dp_rate_limter_t));
    rl->dur = dur;
    rl->dur_cnt_limit = dur_cnt_limit;
    rl->start = get_current_time();
}

//初始化dp线程池
ctrl::ctrl():
      g_running(true)
{
    int thread_id, i;
    for (thread_id=0; thread_id < g_dp_threads; thread_id++){
        dp_thread_data_t *th_data = &g_dp_thread_data[thread_id];      //th_data每个dp线程的数据
        th_data->log_reader = MAX_LOG_ENTRIES -1;
        for (i = 0; i < MAX_LOG_ENTRIES; i ++) {
            auto *hdr = (DPMsgHdr *)th_data->log_ring[i];
            hdr->Kind = DP_KIND_THREAT_LOG;                            //操作类型DP_KIND_THREAT_LOG
            hdr->Length = htons(LOG_ENTRY_SIZE);                       //发送数据包DP_KIND_THREAT_LOG的大小 = 消息头DPMsgHdr大小 + DPMsgThreatlog的大小
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
//    g_running = true;

}

int ctrl::dp_ctrl_handler(int fd) {
    socklen_t len;
    int size, ret = 0;
    char ctrl_msg_buf[BUF_SIZE];

    len = sizeof(struct sockaddr_un);
    size = recvfrom(fd, ctrl_msg_buf, BUF_SIZE - 1, 0, (struct sockaddr *) &g_client_addr, &len);
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
            cout << "dp_ctrl_add_srvc_port" << endl;
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
            cout << "dp_ctrl_cfg_internal_net" << endl;
        } else if (strcmp(key, "ctrl_cfg_specip_net") == 0) {
            cout << "dp_ctrl_cfg_specialip_net" << endl;
        } else if (strcmp(key, "ctrl_cfg_policy_addr") == 0) {
            cout << "dp_ctrl_cfg_internal_net" << endl;
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
    return 0;
}

void ctrl::dp_ctrl_loop() {
    int ret = 0;
    fd_set read_fds;
    int round = 0;
    struct timeval timeout;
    struct timespec last, now;

    strlcpy(THREAD_NAME, "cmd", MAX_THREAD_NAME_LEN);

    rcu_register_thread();

    unlink(DP_SERVER_SOCK);
    //创建通信句柄文件
    g_ctrl_fd = make_named_socket(DP_SERVER_SOCK);               //这个fd用于agent主动向DP发送数据,DP回复
    g_ctrl_notify_fd = make_notify_client(CTRL_NOTIFY_SOCK);     //这个fd用于DP主动向agent发送数据

    /* 互斥锁初始化. */

    clock_gettime(CLOCK_MONOTONIC, &last);
    while (g_running) {
        cout << "等待数据传输" << endl;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        FD_ZERO(&read_fds);
        FD_SET(g_ctrl_fd, &read_fds);
        ret = select(g_ctrl_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        if (ret > 0 && FD_ISSET(g_ctrl_fd, &read_fds)) {
            cout << "接收到agent发送的消息" << endl;
            //调试代码
            dp_ctrl_handler(g_ctrl_fd);
        }

        clock_gettime(CLOCK_MONOTONIC, &now);

        if (now.tv_sec - last.tv_sec >= 2) {
            last = now;
            //发送数据给agent
//            dp_ctrl_update_fqdn_ip();
        }
        round++;
    }

    close(g_ctrl_notify_fd);
    close(g_ctrl_fd);
    unlink(DP_SERVER_SOCK);

    rcu_unregister_thread();
}


//ardp向agent发送二进制数据
int ctrl::dp_ctrl_send_binary(void *data, int len) {
    socklen_t addr_len = sizeof(struct sockaddr_un);

    int sent = sendto(g_ctrl_fd, data, len, 0, (struct sockaddr *) &g_client_addr, addr_len);

    return sent;
}

//ardp向CTRL_NOTIFY_SOCK发送数据
int ctrl::dp_ctrl_notify_ctrl(void *data, int len) {
    // Send binary message actively to ctrl path

    socklen_t addr_len = sizeof(struct sockaddr_un);
    int sent = sendto(g_ctrl_notify_fd, data, len, 0,
                      (struct sockaddr *) &g_ctrl_notify_addr, addr_len);
    return sent;

}

int ctrl::dp_ctrl_keep_alive(json_t *msg) {
    uint32_t seq_num = json_integer_value(json_object_get(msg, "seq_num"));
    uint8_t buf[sizeof(DPMsgHdr) + sizeof(uint32_t)];

    DPMsgHdr *hdr = (DPMsgHdr *) buf;
    hdr->Kind = DP_KIND_KEEP_ALIVE;
    hdr->Length = htons(sizeof(DPMsgHdr) + sizeof(uint32_t));
    hdr->More = 0;

    uint32_t *m = (uint32_t *) (buf + sizeof(DPMsgHdr));
    *m = htonl(seq_num);

    dp_ctrl_send_binary(buf, sizeof(buf));
    return 0;
}

//void ctrl::dp_ctrl_update_fqdn_ip() {
//    dp_ctrl_notify_ctrl(g_notify_msg, sizeof(DPMsgHdr));
//}


