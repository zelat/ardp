//
// Created by Administrator on 2022/7/12.
//

#ifndef ARDP_DOMAIN_SOCKET_CTRL_NOTIFY_H
#define ARDP_DOMAIN_SOCKET_CTRL_NOTIFY_H

#include <sys/un.h>

//这个fd用于DP主动向agent发送数据
namespace dpthreads {
    class DomainSocketCTRLNotify{
    private:
        int ctrl_notify_fd;
        struct sockaddr_un ctrl_notify_addr;
        int Connect(const char *filename);
    public:
        int Init();
        void Exit();
        int SendNotify(void *data, int len);
        int ReceiveBinary(void *data, int len);
    };
};


#endif //ARDP_DOMAIN_SOCKET_CTRL_NOTIFY_H
