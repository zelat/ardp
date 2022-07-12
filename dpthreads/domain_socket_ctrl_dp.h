//
// Created by tanchao on 2022/7/11.
//

#ifndef ARDP_DOMAIN_SOCKET_CTRL_DP_H
#define ARDP_DOMAIN_SOCKET_CTRL_DP_H

#include <string>
#include <sys/un.h>

namespace dpthreads{
    class DomainSocketDPServer{
    private:
        int g_ctrl_fd;
        struct sockaddr_un g_client_addr;
        int Connect(const char *filename);
    public:
        int Init();
        void Exit();
        int SendBinary(void *data, int len);
        int ReceiveBinary(void *data, int len);
    };
}

#endif //ARDP_DOMAIN_SOCKET_CTRL_DP_H
