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

uint32_t g_seconds;
time_t g_start_time;

extern struct timeval g_now;
extern bool g_running;
extern pthread_mutex_t g_debug_lock;

time_t get_current_time()
{
    return (g_start_time + g_seconds);
}

static int debug_ts(FILE *logfp) {
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




