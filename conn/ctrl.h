//
// Created by Administrator on 2022/7/5.
//

#ifndef ARDP_CTRL_H
#define ARDP_CTRL_H

#include <ctime>

class ctrl {
private:
    int g_ctrl_fd;
    int g_ctrl_notify_fd;
    static struct sockaddr_un g_ctrl_notify_addr;
    int make_named_socket(const char * filename);
    int make_notify_client(const char *filename);
public:
    ctrl();
    void dp_ctrl_loop();
};


#endif //ARDP_CTRL_H
