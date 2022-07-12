//
// Created by tanchao on 2022/7/1.
//
#ifndef ARDP_CONFIG_H
#define ARDP_CONFIG_H

#define IFACE_NAME_LEN 32          //网络设备名字长度限制

#define DPI_MAX_PCRE_PATTERNS 16   //PCRE最大匹配个数

#define MAX_DP_THREADS 4           //最大的DP线程数

#define DP_SERVER_SOCK "/tmp/dp_listen.sock"     // dp_ctrl通信

#define CTRL_NOTIFY_SOCK "/tmp/ctrl_listen.sock" // dp_ctrl通信

#define BUF_SIZE 8192                            // dp从agent接收到的packet大小

#define FQDN_IPS_PER_MSG ((DP_MSG_SIZE - sizeof(DPMsgHdr) - sizeof(DPMsgFqdnIpHdr)) / sizeof(DPMsgFqdnIp))

#define AGENT_SUCCESS 0
#define AGENT_FAILED -1
#endif //ARDP_CONFIG_H
