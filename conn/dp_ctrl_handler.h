//
// Created by tanchao on 2022/7/10.
//

#ifndef ARDP_DP_CTRL_HANDLER_H
#define ARDP_DP_CTRL_HANDLER_H


#include <jansson.h>

class dp_ctrl_handler {
private:
    const char *iface;
    json_t *msg;
public:
    dp_ctrl_handler(json_t *msg);
    int dp_ctrl_add_srvc_port(json_t *msg);
};


#endif //ARDP_DP_CTRL_HANDLER_H
