//
// Created by Administrator on 2022/7/26.
//

#ifndef ARDP_LOGGER_H
#define ARDP_LOGGER_H

#include <cstdio>
#include <string>
#include <fstream>

enum{
    DPLOG_LEV_DEBUG ,
    DPLOG_LEV_INFO ,
    DPLOG_LEV_WARNING,
    DPLOG_LEV_ERROR,
    DPLOG_LEV_COUNTER,
};

class DPLogger {
private:
    FILE *logfp;
    struct timeval g_now;
    int logPrint(bool print_ts);
public:
    int debug_stdout(bool print_ts, const char *fmt, va_list args);
    int debug_file(bool print_ts, const char *fmt, va_list args);
private:
    inline bool isFileExist (const std::string& name) {
        std::ifstream f(name.c_str());
        return f.good();
    }
};


#endif //ARDP_LOGGER_H
