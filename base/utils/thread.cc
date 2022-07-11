//
// Created by Administrator on 2022/7/11.
//

#include "thread.h"

namespace base {
    Thread::Thread(const std::string &name)
        :thread_(0), thread_id_(0), continute_(false), running_(false), thread_name_(name){}

    Thread::~Thread() {
        StopThread();
    }

    //创建线程
    bool Thread::StartThread() {
        int err;
        pthread_attr_t attributes;

    }

}