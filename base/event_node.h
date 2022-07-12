//
// Created by tanchao on 2022/7/12.
//

#ifndef ARDP_EVENT_NODE_H
#define ARDP_EVENT_NODE_H

#include <cstdint>

namespace base {
    class EventNode{
    public:
        EventNode(){};
        virtual ~EventNode(){};
        virtual int GetEventFd() = 0;
        virtual uint32_t GetEventType() = 0;
        virtual void OnEventReceived() = 0;
    };
}

#endif //ARDP_EVENT_NODE_H
