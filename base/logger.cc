//
// Created by tanchao on 2022/7/26.
//
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include "base/config/config.h"
#include "logger.h"
#include "base.h"
#include "apis.h"

extern struct timeval g_now;
extern bool g_running;
extern pthread_mutex_t g_debug_lock;

static inline int debug_ts(FILE *logfp) {
    struct timeval now;
    struct tm *tm;

    if (g_now.tv_sec == 0) {
        //gettimeofday(&now, NULL);
        time_t t = get_current_time();
        tm = localtime((const time_t *) &t);
    } else {
        now = g_now;
        tm = localtime(&now.tv_sec);
    }
    printf("%04d-%02d-%02dT%02d:%02d:%02d|DEBU|%s|",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec, THREAD_NAME);
    return fprintf(logfp, "%04d-%02d-%02dT%02d:%02d:%02d|DEBU|%s|",
                   tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                   tm->tm_hour, tm->tm_min, tm->tm_sec, THREAD_NAME);
}

int debug_stdout(bool print_ts, const char *fmt, va_list args) {
    int len = 0;
    pthread_mutex_lock(&g_debug_lock);
    if (print_ts) {
        len = debug_ts(stdout);
    }
    len += vprintf(fmt, args);
    pthread_mutex_unlock(&g_debug_lock);

    return len;
}

int debug_file(bool print_ts, const char *fmt, va_list args) {
    static FILE *logfp = NULL;

    if (logfp == NULL) {
        logfp = fopen(LOG_FILE, "a");

        if (logfp != NULL) {
            int flags;

            if ((flags = fcntl(fileno(logfp), F_GETFL, 0)) == -1) {
                flags = 0;
            }
            fcntl(fileno(logfp), F_SETFL, flags | O_NONBLOCK);
        } else {
            return debug_stdout(print_ts, fmt, args);
        }
    }

    int len = 0;

    pthread_mutex_lock(&g_debug_lock);
    if (print_ts) {
        len = debug_ts(logfp);
    }
    len += vfprintf(logfp, fmt, args);
    fflush(logfp);
    pthread_mutex_unlock(&g_debug_lock);

    return len;
}

/* 修正时间误差 */
void *debug_timer_thr(void *args) {
    snprintf(THREAD_NAME, MAX_THREAD_NAME_LEN, "tmr");
    g_start_time = time(NULL);
    while (g_running) {
        sleep(1);
        g_seconds ++;
        // 每隔30S纪录一次时间
        if ((g_seconds & 0x1f) == 0) {
            time_t time_elapsed = time(NULL) - g_start_time;
            time_t curTime = time(NULL);
            printf("CurrentTime is %s", ctime(&curTime));
            printf("Starttime is %s", ctime(&g_start_time));
            //修正时间误差
            if (time_elapsed > g_seconds) {
//                DEBUG_TIMER("Advance timer for %us\n", time_elapsed - g_seconds);
                std::cout << "Advance timer for " << time_elapsed - g_seconds << std::endl;
                g_seconds = time_elapsed;
            }
        }
    }
    return NULL;
}



