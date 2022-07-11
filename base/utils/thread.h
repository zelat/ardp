//
// Created by tanchao on 2022/7/11.
//

#ifndef ARDP_THREAD_H
#define ARDP_THREAD_H

#include <csignal>
#include <string>

namespace base{
    class Thread {
    private:
        pthread_t thread_;
        pid_t thread_id_;
        bool continute_;
        bool running_;
        std::string thread_name_;
    public:
        Thread(const std::string& name="");
        virtual ~Thread();

        bool StartThread();
        bool StopThread();

        const std::string& thread_name();
        const int thread_id();
        bool IsRunning();
        bool Continue();
        int Cancel();

    private:
        virtual void Run();

        static void *thread_routine(void*);
        void thread_routine();
    };
}
#endif //ARDP_THREAD_H
