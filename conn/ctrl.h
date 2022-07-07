//
// Created by Administrator on 2022/7/5.
//

#ifndef ARDP_CTRL_H
#define ARDP_CTRL_H

#include <ctime>

class ctrl {
private:
    int g_ctrl_fd;
    static struct sockaddr_un g_client_addr;
    int g_ctrl_notify_fd;
    static struct sockaddr_un g_ctrl_notify_addr;
    int g_running;
    int make_named_socket(const char * filename);
    int make_notify_client(const char *filename);
    int dp_ctrl_send_binary(void *data, int len);
    int dp_ctrl_handler(int fd);
public:
    ctrl();
    int dp_ctrl_keep_alive(json_t *msg);
    void dp_ctrl_loop();
};


#endif //ARDP_CTRL_H
