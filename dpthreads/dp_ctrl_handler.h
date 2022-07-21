//
// Created by tanchao on 2022/7/10.
//

#ifndef ARDP_DP_CTRL_HANDLER_H
#define ARDP_DP_CTRL_HANDLER_H


#include <jansson.h>
#include <base/utils/singleton.h>
#include <base/event_handler.h>
#include "domain_socket_ctrl_dp.h"
#include "domain_socket_ctrl_notify.h"
#include "dp_event_cb.h"

    class DP_CTRL_Handler : public base::Singleton<DP_CTRL_Handler>{
    };

#endif //ARDP_DP_CTRL_HANDLER_H