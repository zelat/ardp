//
// Created by tanchao on 2022/6/30.
//

#include <getopt.h>
#include <string.h>
#include <csignal>
#ifdef __cplusplus
extern "C" {
#endif
#include "base/rcu_map.h"
#include "base/debug.h"
#include "base/helper.h"
#ifdef __cplusplus
}
#endif
#include "apis.h"
#include "dpthreads/dp_ctrl_thread.h"

__thread int THREAD_ID;           //线程局部存储
__thread char THREAD_NAME[32];

int g_running;
int g_dp_threads = 0;
int g_stats_slot = 0;
char * g_in_iface;       //网络设备名字
io_config_t g_config;
rcu_map_t g_ep_map;
io_callback_t g_callback;


static int net_run(const char *i_face){
    pthread_t timer_thr;
    pthread_t bld_dlp_thr;
    pthread_t dp_thr[MAX_DP_THREADS];
    int i, timer_thr_id, bld_dlp_thr_id, thr_id[MAX_DP_THREADS];

    g_running = true;

//    signal(SIGTERM, dp_signal_exit);
//    signal(SIGINT, dp_signal_exit);
//    signal(SIGQUIT, dp_signal_exit);

    // 计算dp线程数
    if (g_dp_threads == 0) {
        g_dp_threads = count_cpu();
    }
    if (g_dp_threads > MAX_DP_THREADS) {
        g_dp_threads = MAX_DP_THREADS;
    }

    DP_CTRL_Thread dpCtrlThread;
    dpCtrlThread.Init();

    pthread_create(&timer_thr, NULL, dpCtrlThread.dp_timer_thr, &timer_thr_id);
    pthread_create(&bld_dlp_thr, NULL, dpCtrlThread.dp_bld_dlp_thr, &bld_dlp_thr_id);

    for (i = 0; i < g_dp_threads; i ++) {
        thr_id[i] = i;
        pthread_create(&dp_thr[i], NULL, dpCtrlThread.dp_data_thr, &thr_id[i]);
    }
}

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

//    test_dpi_hs_search dpiHsSearch();
    DP_CTRL_Thread dpCtrlThread;
    dpCtrlThread.Init();
    dpCtrlThread.dp_ctrl_loop();

}