//
// Created by tanchao on 2022/7/12.
//

#include "dp_event_cb.h"

void DP_Event_Callback::OnNetEvent(void *ptr, void *param, int type) {
    DP_Event_Callback *pBaseNetCallback = static_cast<DP_Event_Callback *>(ptr);
    if (pBaseNetCallback) {
        pBaseNetCallback->OnNetEvent(param, type);
    }
}

DP_Event_Callback::DP_Event_Callback(void) {}

DP_Event_Callback::~DP_Event_Callback(void) {}