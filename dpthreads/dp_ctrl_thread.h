//
// Created by tanchao on 2022/7/5.
//

#ifndef ARDP_DP_CTRL_THREAD_H
#define ARDP_DP_CTRL_THREAD_H

#include <ctime>
#include "base.h"
#include "apis.h"
#include "base/config/config.h"
#include "domain_socket_ctrl_dp.h"
#include "domain_socket_ctrl_notify.h"

#define MAX_EPOLL_EVENTS 128



class DP_CTRL_Thread{
private:
    int g_ctrl_fd;                                          //agent与ardp的socket句柄文件
    int g_ctrl_notify_fd;                                   //ctrl发送变更消息的socket句柄文件
    int g_dp_threads;                                       //agent与DP连接的线程数
    uint8_t g_notify_msg[DP_MSG_SIZE];
    dpi_fqdn_hdl_t *g_fqdn_hdl;
    rcu_map_t g_ep_map;
    DomainSocketDPServer socketDpServer;
    DomainSocketCTRLNotify socketCtrlNotify;
public:
    int Init();
    void Exit();
    void dp_ctrl_loop();
    static void *dp_bld_dlp_thr(void *args);
    static void *dp_data_thr(void *args);
private:
    int dp_ctrl_handler();
protected:
    int dp_ctrl_cfg_internal_net(json_t *msg, bool internal);
    int dp_ctrl_add_srvc_port(json_t *msg);
    int dp_ctrl_keep_alive(json_t *msg);
};


#endif //ARDP_DP_CTRL_THREAD_H
