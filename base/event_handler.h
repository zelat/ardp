//
// Created by tanchao on 2022/7/12.
//

#ifndef ARDP_EVENT_HANDLER_H
#define ARDP_EVENT_HANDLER_H

#include "event_node.h"

namespace base {
    class EventHandler {
    public:
        EventHandler();
        virtual ~EventHandler();

        int Init();
        void Exit();

        int AddEventNode(EventNode * node);
        int RemoveEventNode(EventNode *node);
        void Run();
        int GetEventFD();
    private:
        bool g_running;
        int event_fd;
    };
}

#endif
//ARDP_EVENT_HANDLER_H
