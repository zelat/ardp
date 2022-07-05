//
// Created by Administrator on 2022/7/5.
//
#include <sys/un.h>
#include <sys/socket.h>
#ifdef __cplusplus
extern "C"
{
#endif
#include <utils/helper.h>
#ifdef __cplusplus
}
#endif
#include <unistd.h>
#include "ctrl.h"
#include "config.h"

struct sockaddr_un ctrl::g_ctrl_notify_addr;

int ctrl::make_named_socket(const char *filename) {
    struct sockaddr_un name;
    int sock;
    size_t size;

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    name.sun_family = AF_UNIX;
    strlcpy(name.sun_path, filename, sizeof(name.sun_path));

    size = (offsetof(struct sockaddr_un, sun_path) + strlen(name.sun_path));

    if (bind(sock, (struct sockaddr *) &name, size) < 0) {
        return -1;
    }

    return sock;
}

int ctrl::make_notify_client(const char *filename)
{
    int sock;

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    g_ctrl_notify_addr.sun_family = AF_UNIX;
    strlcpy(g_ctrl_notify_addr.sun_path, filename, sizeof(g_ctrl_notify_addr.sun_path));

    return sock;
}

ctrl::ctrl() {}

void ctrl::dp_ctrl_loop() {
    int ret = 0;
    int round = 0;
    struct timeval timeout;
    struct timespec last, now;
    g_ctrl_fd = make_named_socket(DP_SERVER_SOCK);
    g_ctrl_notify_fd = make_notify_client(CTRL_NOTIFY_SOCK);

    close(g_ctrl_notify_fd);
    close(g_ctrl_fd);
}