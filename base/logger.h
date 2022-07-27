//
// Created by Administrator on 2022/7/26.
//

#ifndef ARDP_LOGGER_H
#define ARDP_LOGGER_H

void *debug_timer_thr(void *args);

int debug_stdout(bool print_ts, const char *fmt, va_list args);

int debug_file(bool print_ts, const char *fmt, va_list args);


#endif //ARDP_LOGGER_H
