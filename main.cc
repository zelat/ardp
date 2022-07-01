//
// Created by tanchao on 2022/6/30.
//

#include <getopt.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "utils/rcu_map.h"
#include "apis.h"
#include "debug.h"
#ifdef __cplusplus
}
#endif

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

}