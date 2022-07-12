//
// Created by Administrator on 2022/7/12.
//

#ifndef ARDP_DP_EVENT_CB_H
#define ARDP_DP_EVENT_CB_H

namespace dpthreads {
    class DP_Event_Callback{
    public:
        static void OnNetEvent(void* ptr, void *param, int type);
        virtual void OnNetEvent( void *param, int type) = 0;
        DP_Event_Callback(void);
        virtual ~DP_Event_Callback(void);
    };
}

#endif //ARDP_DP_EVENT_CB_H
