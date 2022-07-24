//
// Created by tanchao on 2022/6/30.
//

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
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
#include "base/config/config.h"
#include "dpthreads/dp_pkt.h"
#include "dpthreads/dp_ctrl_thread.h"

extern int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id);

__thread int THREAD_ID;           //线程局部存储
__thread char THREAD_NAME[32];

dp_mnt_shm_t *g_shm;
int g_dp_threads = 0;
int g_stats_slot = 0;
char * g_in_iface;       //网络设备名字
io_config_t g_config;
rcu_map_t g_ep_map;
io_callback_t g_callback;
int DP_CTRL_Thread::g_running = true;

static void *get_shm(size_t size)
{
    int fd;
    void *ptr;

    fd = shm_open(DP_MNT_SHM_NAME, O_RDWR, S_IRWXU | S_IRWXG);
    if (fd < 0) {
        return NULL;
    }

    ptr = mmap(NULL, sizeof(dp_mnt_shm_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED || ptr == NULL) {
        close(fd);
        return NULL;
    }

    close(fd);

    return ptr;
}

static int net_run(const char *iface){
    pthread_t timer_thr;
    pthread_t bld_dlp_thr;
    pthread_t dp_thr[MAX_DP_THREADS];
    int i, timer_thr_id, bld_dlp_thr_id, thr_id[MAX_DP_THREADS];

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

    pthread_create(&timer_thr, NULL, &DP_CTRL_Thread::dp_timer_thr, &timer_thr_id);
    pthread_create(&bld_dlp_thr, NULL, &DP_CTRL_Thread::dp_bld_dlp_thr, &bld_dlp_thr_id);

    for (i = 0; i < g_dp_threads; i ++) {
        thr_id[i] = i;
        pthread_create(&dp_thr[i], NULL, &DP_CTRL_Thread::dp_data_thr, &thr_id[i]);
    }

    if (iface != NULL) {
        sleep(2);
        dp_data_add_tap("/proc/1/ns/net", iface, "11:22:33:44:55:66", 0);
    }

    dpCtrlThread.dp_ctrl_loop();

    pthread_join(timer_thr, NULL);
    pthread_join(bld_dlp_thr, NULL);
    for (i = 0; i < g_dp_threads; i ++) {
        pthread_join(dp_thr[i], NULL);
    }
    return 0;
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
    g_shm = (dp_mnt_shm_t *)get_shm(sizeof(dp_mnt_shm_t));
    if (g_shm == NULL) {
        DEBUG_INIT("Unable to get shared memory.\n");
        return -1;
    }
    int ret = net_run(g_in_iface);

    return ret;
}