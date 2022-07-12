//
// Created by tanchao on 2022/6/30.
//

#include <getopt.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "base/rcu_map.h"
#include "apis.h"
#include "base/debug.h"
#ifdef __cplusplus
}
#endif

#include "dpi/sig/dpi_hs_search.h"
#include "dpthreads/dp_ctrl_thread.h"

__thread int THREAD_ID;           //线程局部存储
__thread char THREAD_NAME[32];

char * g_in_iface;       //网络设备名字
io_config_t g_config;
rcu_map_t g_ep_map;
io_callback_t g_callback;

int main(int argc, char **argv){
    int arg = 0;
    while (arg != -1) {
        arg = getopt(argc, argv, "hcd:i:j:n:p:s");
        switch (arg) {
            case -1:
                break;
            case 'i':
                g_in_iface = strdup(optarg);
                g_config.promisc = true;
                break;
            case 'd':
                if (strcasecmp(optarg, "none") == 0) {
                    g_debug_levels = 0;
                } else if (optarg[0] == '-') {
                    g_debug_levels &= ~debug_name2level(optarg + 1);
                } else {
                    g_debug_levels |= debug_name2level(optarg);
                }
                break;
            default:
                exit(-2);
        }
    }

//    dpi_hs_search dpiHsSearch();
    dpthreads::DP_CTRL_Thread dpCtrlThread;
    dpCtrlThread.Init();
    dpCtrlThread.dp_ctrl_loop();

}