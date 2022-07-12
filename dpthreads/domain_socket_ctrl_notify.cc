//
// Created by tanchao on 2022/7/12.
//

#ifdef __cplusplus
extern "C" {
#endif
#include "base/helper.h"
#ifdef __cplusplus
}
#endif

#include <iostream>
#include <unistd.h>
#include "base/config/config.h"
#include "domain_socket_ctrl_notify.h"

namespace dpthreads {
    int DomainSocketCTRLNotify::Init() {
        const char *server_name(DP_SERVER_SOCK);
        if((g_ctrl_notify_fd = Connect(server_name)) < 0)
        {
            std::cout << "DomainSocketClient" <<  "Connect to server failed." << std::endl;
        }
        return g_ctrl_notify_fd;
    }

    void DomainSocketCTRLNotify::Exit(){
        if(g_ctrl_notify_fd > 0){
            close(g_ctrl_notify_fd);
        }
    }

    int DomainSocketCTRLNotify::Connect(const char *filename) {
        int sock;

        sock = socket(PF_UNIX, SOCK_DGRAM, 0);
        if (sock < 0) {
            return -1;
        }

        g_ctrl_notify_addr.sun_family = AF_UNIX;
        strlcpy(g_ctrl_notify_addr.sun_path, filename, sizeof(g_ctrl_notify_addr.sun_path));

        return sock;
    }

    //ardp向CTRL_NOTIFY_SOCK发送数据
    int DomainSocketCTRLNotify::SendNotify(void *data, int len) {
        // Send binary message actively to ctrl path
        socklen_t addr_len = sizeof(struct sockaddr_un);
        int sent = sendto(g_ctrl_notify_fd, data, len, 0,
                          (struct sockaddr *) &g_ctrl_notify_addr, addr_len);
        return sent;

    }
}