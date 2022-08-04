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
#include <iostream>
#ifdef __cplusplus
extern "C" {
#endif
#include "base/rcu_map.h"
#include "base/debug.h"
#include "base/helper.h"
#ifdef __cplusplus
}
#endif
#include "base/logger.h"
#include "apis.h"
#include "dpthreads/dp_ctrl_thread.h"

extern int dp_data_add_tap(const char *netns, const char *iface, const char *ep_mac, int thr_id);

__thread int THREAD_ID;           //线程局部存储
__thread char THREAD_NAME[32];

struct timeval g_now;
dp_mnt_shm_t *g_shm;
int g_dp_threads = 0;
int g_stats_slot = 0;
char *g_in_iface;       //网络设备名字
io_config_t g_config;
rcu_map_t g_ep_map;
io_callback_t g_callback;
int g_running;
pthread_mutex_t g_debug_lock;
struct cds_list_head g_subnet4_list;
struct cds_list_head g_subnet6_list;

dp_thread_data_t g_dp_thread_data[MAX_DP_THREADS];

/* 中断dp的运行 */
static void dp_signal_exit(int num) {
    g_running = false;
}

/* 创建共享内存区 */
template <typename T>
T *get_shm(size_t size) {
    int fd;
    void *ptr;

    //创建共享内存文件(/dev/shm/dp_mnt.shm)
    fd = shm_open(DP_MNT_SHM_NAME, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG);
    if (fd < 0) {
        return NULL;
    }
    //将dp_mnt.shm共享内存文件映射到内存，MAP_SHARED建立进程间共享，用于进程间通信
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED || ptr == NULL) {
        close(fd);
        return NULL;
    }

    close(fd);

    return static_cast<T *>(ptr);
}

static int net_run(const char *iface) {
    pthread_t timer_thr;
    pthread_t bld_dlp_thr;
    pthread_t dp_thr[MAX_DP_THREADS];
    int i, timer_thr_id, bld_dlp_thr_id, thr_id[MAX_DP_THREADS];

    g_running = true;
    // 发送中断信号
    signal(SIGTERM, dp_signal_exit);
    signal(SIGINT, dp_signal_exit);
    signal(SIGQUIT, dp_signal_exit);

    // 计算dp线程数
    if (g_dp_threads == 0) {
        g_dp_threads = count_cpu();
    }
    if (g_dp_threads > MAX_DP_THREADS) {
        g_dp_threads = MAX_DP_THREADS;
    }

    DP_CTRL_Thread dpCtrlThread;
    dpCtrlThread.Init(g_dp_thread_data);

    pthread_create(&timer_thr, NULL, debug_timer_thr, &timer_thr_id);
//    pthread_create(&bld_dlp_thr, NULL, &DP_CTRL_Thread::dp_bld_dlp_thr, &bld_dlp_thr_id);

    for (i = 0; i < g_dp_threads; i++) {
        thr_id[i] = i;
        pthread_create(&dp_thr[i], NULL, dp_data_thr, &thr_id[i]);
    }
    //新建一个tap设备
    if (iface != NULL) {
        sleep(2);
        dp_data_add_tap("/proc/1/ns/net", iface, "11:22:33:44:55:66", 0);
    }

    dpCtrlThread.dp_ctrl_loop();

    pthread_join(timer_thr, NULL);
    pthread_join(bld_dlp_thr, NULL);
    for (i = 0; i < g_dp_threads; i++) {
        pthread_join(dp_thr[i], NULL);
    }
    return 0;
}


static int dp_ep_match(struct cds_lfht_node *ht_node, const void *key) {
    io_mac_t *ht_mac = STRUCT_OF(ht_node, io_mac_t, node);
    const uint8_t *mac = (uint8_t *)key;

    return memcmp(mac, &ht_mac->mac, sizeof(ht_mac->mac)) == 0 ? 1 : 0;
}

static uint32_t dp_ep_hash(const void *key) {
    return sdbm_hash((uint8_t *)key, ETH_ALEN);
}

int main(int argc, char **argv) {
    int arg = 0;
    //是否传入PCAP文件
    char *pcap = NULL;
    //CPU限制
    struct rlimit core_limits;
    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core_limits);                // 设置CPU使用限制
    //清空一个g_config结构类型的变量, 对定义的字符串进行初始化为‘0’
    memset(&g_config, 0, sizeof(g_config));

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

    setlinebuf(stdout);
    pthread_mutex_init(&g_debug_lock, NULL);
    rcu_map_init(&g_ep_map, 1, offsetof(io_mac_t, node), dp_ep_match, dp_ep_hash);
    CDS_INIT_LIST_HEAD(&g_subnet4_list);
    CDS_INIT_LIST_HEAD(&g_subnet6_list);

    g_callback.debug = debug_stdout;
    dpi_setup(&g_callback, &g_config);

//    test_dpi_hs_search dpiHsSearch();
    g_shm = get_shm<dp_mnt_shm_t>(sizeof(dp_mnt_shm_t));
    if (g_shm == NULL) {
        printf("Unable to get shared memory.\n");
        return -1;
    }

    int ret = net_run(g_in_iface);

    munmap(g_shm, sizeof(dp_mnt_shm_t));
    return ret;
}