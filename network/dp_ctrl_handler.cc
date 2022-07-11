//
// Created by Administrator on 2022/7/10.
//

#include "dp_ctrl_handler.h"

dp_ctrl_handler::dp_ctrl_handler(json_t *msg) {

}

int dp_ctrl_handler::dp_ctrl_add_srvc_port(json_t *msg) {
    const char *iface;
    json_t *jumboframe_obj;
    bool jumboframe = false;

    jumboframe_obj = json_object_get(msg, "jumboframe");
    if (jumboframe_obj != NULL) {
        jumboframe = json_boolean_value(jumboframe_obj);
    }

    iface = json_string_value(json_object_get(msg, "iface"));
    printf("iface=%s, jumboframe=%d\n", iface, jumboframe);

    return 0;
}
