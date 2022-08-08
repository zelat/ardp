//
// Created by tanchao on 2022/7/5.
//
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include "urcu/rcuhlist.h"
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
#include "dp_ctrl_thread.h"
#include "dp_pkt.h"
#include "dpi/dpi_policy.h"

using namespace std;

#define RELEASED_CTX_TIMEOUT 5      // 10 second
#define RELEASED_CTX_PRUNE_FREQ 5   // 10 second
#define DP_STATS_FREQ 60            // 1 minute

uint32_t g_sess_id_to_clear = 0;
struct ether_addr *g_mac_addr_to_del = NULL;

pthread_cond_t g_ctrl_req_cond;
pthread_mutex_t g_ctrl_req_lock;
pthread_cond_t g_dlp_ctrl_req_cond;
pthread_mutex_t g_dlp_ctrl_req_lock;

io_internal_subnet4_t *g_internal_subnet4;
io_internal_subnet4_t *g_policy_addr;

io_spec_internal_subnet4_t *g_specialip_subnet4;
uint8_t g_xff_enabled = 0;

extern DP_Ring dpRing;
extern int g_running;
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

static uint32_t ep_app_hash(const void *key)
{
    const io_app_t *app = (io_app_t *)key;
    return app->port ^ app->ip_proto;
}

static int ep_app_match(struct cds_lfht_node *ht_node, const void *key)
{
    io_app_t *app = STRUCT_OF(ht_node, io_app_t, node);
    const io_app_t *k = (io_app_t *)key;
    return app->port == k->port && app->ip_proto == k->ip_proto;
}

static uint32_t ep_dlp_cfg_hash(const void *key)
{
    const io_dlp_cfg_t *dlpcfg = (io_dlp_cfg_t *)key;
    return sdbm_hash((uint8_t *)&dlpcfg->sigid, sizeof(uint32_t));
}

static int ep_dlp_cfg_match(struct cds_lfht_node *ht_node, const void *key)
{
    io_dlp_cfg_t *dlpcfg = STRUCT_OF(ht_node, io_dlp_cfg_t, node);
    const io_dlp_cfg_t *k = (io_dlp_cfg_t *)key;
    return dlpcfg->sigid == k->sigid;
}

static uint32_t ep_dlp_ruleid_hash(const void *key)
{
    const io_dlp_ruleid_t *dlprid = (io_dlp_ruleid_t *)key;
    return sdbm_hash((uint8_t *)&dlprid->rid, sizeof(uint32_t));
}

static int ep_dlp_ruleid_match(struct cds_lfht_node *ht_node, const void *key)
{
    io_dlp_ruleid_t *dlprid = STRUCT_OF(ht_node, io_dlp_ruleid_t, node);
    const io_dlp_ruleid_t *k = (io_dlp_ruleid_t *)key;
    return dlprid->rid == k->rid;
}

static void ep_app_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->app_map, node) {
        io_app_t *app = STRUCT_OF(node, io_app_t, node);
        rcu_map_del(&ep->app_map, app);
        free(app);
    }
    rcu_map_destroy(&ep->app_map);
}

static void ep_dlp_cfg_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->dlp_cfg_map, node) {
        io_dlp_cfg_t *dlpcfg = STRUCT_OF(node, io_dlp_cfg_t, node);
        rcu_map_del(&ep->dlp_cfg_map, dlpcfg);

        if (dlpcfg->sig_user_list.prev == NULL && dlpcfg->sig_user_list.next == NULL) {
            CDS_INIT_LIST_HEAD(&dlpcfg->sig_user_list);
        }

        dpi_sig_user_link_t *sig_user_itr, *sig_user_next;
        cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, &dlpcfg->sig_user_list, node) {
            cds_list_del((struct cds_list_head *)sig_user_itr);
            if (sig_user_itr->sig_user) {
                free(sig_user_itr->sig_user);
            }
            free(sig_user_itr);
        }
        free(dlpcfg);
    }
    rcu_map_destroy(&ep->dlp_cfg_map);
}

static void ep_waf_cfg_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->waf_cfg_map, node) {
        io_dlp_cfg_t *wafcfg = STRUCT_OF(node, io_dlp_cfg_t, node);
        rcu_map_del(&ep->waf_cfg_map, wafcfg);

        if (wafcfg->sig_user_list.prev == NULL && wafcfg->sig_user_list.next == NULL) {
            CDS_INIT_LIST_HEAD(&wafcfg->sig_user_list);
        }

        dpi_sig_user_link_t *sig_user_itr, *sig_user_next;
        cds_list_for_each_entry_safe(sig_user_itr, sig_user_next, &wafcfg->sig_user_list, node) {
            cds_list_del((struct cds_list_head *)sig_user_itr);
            if (sig_user_itr->sig_user) {
                free(sig_user_itr->sig_user);
            }
            free(sig_user_itr);
        }
        free(wafcfg);
    }
    rcu_map_destroy(&ep->waf_cfg_map);
}

static void ep_dlp_rid_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->dlp_rid_map, node) {
        io_dlp_ruleid_t *dlprid = STRUCT_OF(node, io_dlp_ruleid_t, node);
        rcu_map_del(&ep->dlp_rid_map, dlprid);
        free(dlprid);
    }
    rcu_map_destroy(&ep->dlp_rid_map);
}

static void ep_waf_rid_destroy(io_ep_t *ep)
{
    struct cds_lfht_node *node;
    RCU_MAP_FOR_EACH(&ep->waf_rid_map, node) {
        io_dlp_ruleid_t *wafrid = STRUCT_OF(node, io_dlp_ruleid_t, node);
        rcu_map_del(&ep->waf_rid_map, wafrid);
        free(wafrid);
    }
    rcu_map_destroy(&ep->waf_rid_map);
}

static void dp_pips_destroy(io_ep_t *ep)
{
    if (ep->pips) {
        free(ep->pips);
    }
}

static void ep_destroy(io_ep_t *ep)
{
    ep_app_destroy(ep);
    dp_policy_destroy(ep->policy_hdl);
    ep_dlp_cfg_destroy(ep);
    ep_waf_cfg_destroy(ep);
    ep_dlp_rid_destroy(ep);
    ep_waf_rid_destroy(ep);
    dp_dlp_destroy(ep->dlp_detector);
    dp_pips_destroy(ep);
}

//对经过dp的流量进行限速
static void dp_rate_limiter_reset(dp_rate_limter_t *rl, uint16_t dur, uint16_t dur_cnt_limit) {
    memset(rl, 0, sizeof(dp_rate_limter_t));
    rl->dur = dur;
    rl->dur_cnt_limit = dur_cnt_limit;
    rl->start = get_current_time();
}

//初始化dp线程池
int DP_CTRL_Thread::Init(dp_thread_data_t *dp_thread_data) {
    int thread_id, i;
    for (thread_id = 0; thread_id < g_dp_threads; thread_id++) {
        dp_thread_data_t *th_data = &dp_thread_data[thread_id];      //th_data每个dp线程的数据
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
//            ret = dp_ctrl_add_port_pair(msg);
        } else if (strcmp(key, "ctrl_del_port_pair") == 0) {
            cout << "dp_ctrl_del_port_pair" << endl;
        } else if (strcmp(key, "ctrl_add_tap_port") == 0) {
            ret = dp_ctrl_add_tap_port(msg);
        } else if (strcmp(key, "ctrl_del_tap_port") == 0) {
            cout << "dp_ctrl_del_tap_port" << endl;
        } else if (strcmp(key, "ctrl_add_nfq_port") == 0) {
            cout << "dp_ctrl_add_nfq_port" << endl;
        } else if (strcmp(key, "ctrl_del_nfq_port") == 0) {
            cout << "dp_ctrl_del_nfq_port" << endl;
        } else if (strcmp(key, "ctrl_add_mac") == 0) {
            ret = dp_ctrl_add_mac(msg);
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
            ret = dp_ctrl_cfg_policy(msg);
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

//接收规则列表
int DP_CTRL_Thread::dp_ctrl_cfg_policy(json_t *msg){
    int cmd;
    json_t *obj, *rule_obj, *app_obj, *app_rule_obj;
    dpi_policy_t policy;
    int i, j;
    int flag;
    int ret = 0;

    cmd = json_integer_value(json_object_get(msg, "cmd"));
    flag = json_integer_value(json_object_get(msg, "flag"));
    policy.def_action = json_integer_value(json_object_get(msg, "defact"));
    policy.apply_dir = json_integer_value(json_object_get(msg, "dir"));
    //判断消息中是否包含mac地址
    obj = json_object_get(msg, "mac");
    policy.num_macs = json_array_size(obj);
    if (!policy.num_macs) {
        DEBUG_ERROR(DBG_CTRL, "Missing mac address in policy cfg!!\n");
        return -1;
    }

    policy.mac_list = (ether_addr *)calloc(sizeof(struct ether_addr), policy.num_macs);
    if (!policy.mac_list) {
        DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
        return -1;
    }

    for (i = 0; i < policy.num_macs; i++) {
        const char *mac_str = json_string_value(json_array_get(obj, i));
        ether_aton_r(mac_str, &policy.mac_list[i]);
    }

    obj = json_object_get(msg, "rules");
    policy.num_rules = json_array_size(obj);
    if (policy.num_rules) {
        policy.rule_list = (dpi_policy_rule_t *)calloc(policy.num_rules, sizeof(dpi_policy_rule_t));
        if (!policy.rule_list) {
            DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
            free(policy.mac_list);
            return -1;
        }
    } else {
        policy.rule_list = NULL;
    }

    for (i = 0; i < policy.num_rules; i ++) {
        json_t *ip_obj, *fqdn_obj;
        rule_obj = json_array_get(obj, i);
        policy.rule_list[i].id = json_integer_value(json_object_get(rule_obj, "id"));
        policy.rule_list[i].sip = inet_addr(json_string_value(json_object_get(rule_obj, "sip")));
        policy.rule_list[i].dip = inet_addr(json_string_value(json_object_get(rule_obj, "dip")));
        ip_obj = json_object_get(rule_obj, "sipr");
        if (ip_obj) {
            policy.rule_list[i].sip_r = inet_addr(json_string_value(ip_obj));
        } else {
            policy.rule_list[i].sip_r = policy.rule_list[i].sip;
        }
        ip_obj = json_object_get(rule_obj, "dipr");
        if (ip_obj) {
            policy.rule_list[i].dip_r = inet_addr(json_string_value(ip_obj));
        } else {
            policy.rule_list[i].dip_r = policy.rule_list[i].dip;
        }
        policy.rule_list[i].dport = json_integer_value(json_object_get(rule_obj, "port"));
        policy.rule_list[i].dport_r = json_integer_value(json_object_get(rule_obj, "portr"));
        policy.rule_list[i].proto = json_integer_value(json_object_get(rule_obj, "proto"));
        policy.rule_list[i].action = json_integer_value(json_object_get(rule_obj, "action"));
        policy.rule_list[i].ingress = json_boolean_value(json_object_get(rule_obj, "ingress"));
        fqdn_obj = json_object_get(rule_obj,"fqdn");
        if (fqdn_obj != NULL) {
            strlcpy(policy.rule_list[i].fqdn, json_string_value(fqdn_obj), MAX_FQDN_LEN);
        }
        app_obj = json_object_get(rule_obj,"apps");
        if (app_obj != NULL) {
            int num_apps = json_array_size(app_obj);
            dpi_policy_app_rule_t *app_rule = (dpi_policy_app_rule_t *)calloc(num_apps, sizeof(dpi_policy_app_rule_t));
            if (!app_rule) {
                DEBUG_ERROR(DBG_CTRL, "out of memory!!\n");
                ret = -1;
                goto cleanup;
            }
            policy.rule_list[i].num_apps = num_apps;
            policy.rule_list[i].app_rules = app_rule;
            for (j = 0; j < num_apps; j++) {
                app_rule_obj = json_array_get(app_obj, j);
                app_rule->rule_id = json_integer_value(json_object_get(app_rule_obj, "rid"));
                app_rule->app = json_integer_value(json_object_get(app_rule_obj, "app"));
                app_rule->action = json_integer_value(json_object_get(app_rule_obj, "action"));
                app_rule++;
            }
        }
    }

    dpi_policy_cfg(cmd, &policy, flag);
    cleanup:
    free(policy.mac_list);
    if (policy.rule_list) {
        for (i = 0; i < policy.num_rules; i ++) {
            if (policy.rule_list[i].app_rules)  {
                free(policy.rule_list[i].app_rules);
            }
        }
        free(policy.rule_list);
    }
    return ret;
}

// 创建mac地址
int DP_CTRL_Thread::dp_ctrl_add_mac(json_t *msg) {
    void *buf;
    io_ep_t *ep;
    io_mac_t *mac, *ucmac, *bcmac;
    struct ether_addr oldmac;
    const char *mac_str, *ucmac_str, *bcmac_str, *oldmac_str, *pmac_str;
    const char *iface;
    int i, count=0;
    json_t *obj, *nw_obj;
    io_internal_pip_t *pips = NULL;

    iface = json_string_value(json_object_get(msg, "iface"));
    mac_str = json_string_value(json_object_get(msg, "mac"));
    ucmac_str = json_string_value(json_object_get(msg, "ucmac"));
    bcmac_str = json_string_value(json_object_get(msg, "bcmac"));
    oldmac_str = json_string_value(json_object_get(msg, "oldmac"));
    pmac_str = json_string_value(json_object_get(msg, "pmac"));
    obj = json_object_get(msg, "pips");
    if (obj) {
        count = json_array_size(obj);
        pips = (io_internal_pip_t *)calloc(sizeof(io_internal_pip_t) + count * sizeof(io_pip_t), 1);
        if (!pips) {
            DEBUG_ERROR(DBG_CTRL, "out of memory!!\n")
            return -1;
        }
        pips->count = count;
        for (i = 0; i < count; i++) {
            nw_obj = json_array_get(obj, i);
            pips->list[i].ip = inet_addr(json_string_value(json_object_get(nw_obj, "ip")));
        }
    }

    DEBUG_CTRL("mac=%s ucmac=%s oldmac=%s pmac=%s\n", mac_str, ucmac_str, oldmac_str, pmac_str);

    buf = calloc(1, sizeof(io_mac_t) * 3 + sizeof(*ep));
    if (buf == NULL) return -1;

    mac = (io_mac_t *)buf;
    ucmac = (io_mac_t *)((io_mac_t *)buf + sizeof(io_mac_t));
    bcmac = (io_mac_t *)((io_mac_t *)buf + sizeof(io_mac_t) * 2);
    ep = (io_ep_t *)((io_ep_t *)buf + sizeof(io_mac_t) * 3);
    ep->mac = mac;
    ep->ucmac = ucmac;
    ep->bcmac = bcmac;
    ep->cassandra_svr = false;
    ep->kafka_svr = false;
    ep->couchbase_svr = false;
    ep->zookeeper_svr = false;

    ether_aton_r(mac_str, &mac->mac);
    mac->ep = ep;
    if (strlen(ucmac_str) > 0) {
        ether_aton_r(ucmac_str, &ucmac->mac);
        ucmac->unicast = 1;
        ucmac->ep = ep;
    }
    if (strlen(bcmac_str) > 0) {
        ether_aton_r(bcmac_str, &bcmac->mac);
        bcmac->broadcast = 1;
        bcmac->ep = ep;
    }
    if (strlen(oldmac_str) > 0) {
        ether_aton_r(oldmac_str, &oldmac);
    } else {
        oldmac = mac->mac;
    }
    //for proxymesh ep, we need original ep's MAC to get policy handle
    if (strlen(pmac_str) > 0) {
        ether_aton_r(pmac_str, &ep->pmac);
    }
    //proxymesh ep, we need original ep's IPs to do xff policy match
    //for 5-tuple whose src and dst IP is 127.0.0.x
    ep->pips = pips;

    strlcpy(ep->iface, iface, sizeof(ep->iface));

    // Add to map
    // Although MAC of a container port doesn't change, UCMAC and BCMAC can be added (tap->inline)
    // or changed (switching between tap and inline back and forth)
    void *old_buf;

    rcu_read_lock();
    old_buf = rcu_map_lookup(&g_ep_map, &oldmac);
    if (old_buf != NULL) {
        /* keep the old policy hdl if any */
        io_ep_t *old_ep;
        old_ep = (io_ep_t *)((io_ep_t *)old_buf + sizeof(io_mac_t) * 3);

        memcpy(&ep->COPY_START, &old_ep->COPY_START, sizeof(io_ep_t) - offsetof(io_ep_t, COPY_START));
        DEBUG_CTRL("copy existing ep, policy hdl %p.\n", old_ep->policy_hdl);

        // Remove the old unicast/broadcast mac entry
        rcu_map_del(&g_ep_map, old_buf);

        io_mac_t *old_ucmac = (io_mac_t *)old_buf + sizeof(io_mac_t);
        if (!mac_zero(old_ucmac->mac.ether_addr_octet)) {
            rcu_map_del(&g_ep_map, old_ucmac);
        }
        io_mac_t *old_bcmac = (io_mac_t *)old_buf + sizeof(io_mac_t) * 2;
        if (!mac_zero(old_bcmac->mac.ether_addr_octet)) {
            rcu_map_del(&g_ep_map, old_bcmac);
        }

        // Add the new mac entry
        rcu_map_add(&g_ep_map, mac, &mac->mac);
        if (!mac_zero(ucmac->mac.ether_addr_octet)) {
            rcu_map_add_replace(&g_ep_map, ucmac, &ucmac->mac);
        }
        if (!mac_zero(bcmac->mac.ether_addr_octet)) {
            rcu_map_add_replace(&g_ep_map, bcmac, &bcmac->mac);
        }

        rcu_read_unlock();
        synchronize_rcu();

        // Pointers are copied to the new ep. Reset pointers in the old ep to prevent data from being destroyed.
        old_ep->policy_hdl = NULL;
        rcu_map_init(&old_ep->app_map, 8, offsetof(io_app_t, node), ep_app_match, ep_app_hash);
        //dlp
        old_ep->dlp_detector = NULL;
        rcu_map_init(&old_ep->dlp_cfg_map, 8, offsetof(io_dlp_cfg_t, node), ep_dlp_cfg_match, ep_dlp_cfg_hash);
        rcu_map_init(&old_ep->waf_cfg_map, 8, offsetof(io_dlp_cfg_t, node), ep_dlp_cfg_match, ep_dlp_cfg_hash);
        rcu_map_init(&old_ep->dlp_rid_map, 8, offsetof(io_dlp_ruleid_t, node), ep_dlp_ruleid_match, ep_dlp_ruleid_hash);
        rcu_map_init(&old_ep->waf_rid_map, 8, offsetof(io_dlp_ruleid_t, node), ep_dlp_ruleid_match, ep_dlp_ruleid_hash);
        ep_destroy(old_ep);

        free(old_buf);

        DEBUG_CTRL("replace %s to ep map.\n", mac_str);
    } else {
        rcu_map_init(&ep->app_map, 8, offsetof(io_app_t, node), ep_app_match, ep_app_hash);
        rcu_map_init(&ep->dlp_cfg_map, 8, offsetof(io_dlp_cfg_t, node), ep_dlp_cfg_match, ep_dlp_cfg_hash);
        rcu_map_init(&ep->waf_cfg_map, 8, offsetof(io_dlp_cfg_t, node), ep_dlp_cfg_match, ep_dlp_cfg_hash);
        rcu_map_init(&ep->dlp_rid_map, 8, offsetof(io_dlp_ruleid_t, node), ep_dlp_ruleid_match, ep_dlp_ruleid_hash);
        rcu_map_init(&ep->waf_rid_map, 8, offsetof(io_dlp_ruleid_t, node), ep_dlp_ruleid_match, ep_dlp_ruleid_hash);
        ep->tap = true;

        rcu_map_add(&g_ep_map, mac, &mac->mac);
        if (!mac_zero(ucmac->mac.ether_addr_octet)) {
            rcu_map_add_replace(&g_ep_map, ucmac, &ucmac->mac);
        }
        if (!mac_zero(bcmac->mac.ether_addr_octet)) {
            rcu_map_add_replace(&g_ep_map, bcmac, &bcmac->mac);
        }

        rcu_read_unlock();
        DEBUG_CTRL("add %s to ep map.\n", mac_str);
    }
}

void *DP_CTRL_Thread::dp_bld_dlp_thr(void *args) {
    return nullptr;
}

int DP_CTRL_Thread::dp_ctrl_add_tap_port(json_t *msg) {
    const char *netns, *iface, *ep_mac;

    netns = json_string_value(json_object_get(msg, "netns"));
    iface = json_string_value(json_object_get(msg, "iface"));
    ep_mac = json_string_value(json_object_get(msg, "epmac"));
    DEBUG_CTRL("netns=%s iface=%s\n", netns, iface);

    return dp_data_add_tap(netns, iface, ep_mac, 0);
}


