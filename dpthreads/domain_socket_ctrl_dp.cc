//
// Created by Administrator on 2022/7/11.
//

#include <stdio.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "base/helper.h"
#ifdef __cplusplus
}
#endif

#include <iostream>
#include "base/config/config.h"
#include "domain_socket_ctrl_dp.h"

namespace dpthreads {
    int DomainSocketDPServer::Init() {
        const char *server_name(DP_SERVER_SOCK);
        if((g_ctrl_fd = Connect(server_name)) < 0)
        {
            std::cout << "DomainSocketClient" <<  "Connect to server failed." << std::endl;
        }
        return g_ctrl_fd;
    }

    void DomainSocketDPServer::Exit(){
        if(g_ctrl_fd > 0){
            close(g_ctrl_fd);
        }
    }


    int DomainSocketDPServer::Connect(const char *filename) {
        struct sockaddr_un name;
        int sock;
        size_t size;

        /* create a Unix domain stream socket */
        sock = socket(PF_UNIX, SOCK_DGRAM, 0);
        if (sock < 0) {
            return -1;
        }

        name.sun_family = AF_UNIX;
        strlcpy(name.sun_path, filename, sizeof(name.sun_path));

        size = (offsetof(struct sockaddr_un, sun_path) + strlen(name.sun_path));
        /* bind the name to the descriptor */
        if (bind(sock, (struct sockaddr *) &name, size) < 0) {
            return -1;
        }

        return sock;
    }

    int DomainSocketDPServer::SendBinary(void *data, int len){
        socklen_t addr_len = sizeof(struct sockaddr_un);
        int sent = sendto(g_ctrl_fd, data, len, 0,
                                (struct sockaddr *)&g_client_addr , addr_len);
        return sent;
    }

    int DomainSocketDPServer::ReceiveBinary(void *data, int len){
        socklen_t addr_len = sizeof(struct sockaddr_un);;
        int receive = recvfrom(g_ctrl_fd, data, len, 0,
                               (struct sockaddr *)&g_client_addr, &addr_len);
        return receive;
    }
}