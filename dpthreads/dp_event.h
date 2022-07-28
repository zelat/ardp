//
// Created by Administrator on 2022/7/12.
//

#ifndef ARDP_DP_EVENT_H
#define ARDP_DP_EVENT_H

#include "base/event_node.h"
#include "dp_types.h"

#define MAX_EPOLL_EVENTS 128

class DP_Event {
public:
    DP_Event(int threadID);
    virtual ~DP_Event();
    int Init();
    void Exit();
    int AddEventNode(dp_context_t *ctx);
    int RemoveEventNode(dp_context_t *ctx);
    void Run();
    int GetEventFd();
private:
    int thr_id;
    struct epoll_event epoll_evs[MAX_EPOLL_EVENTS];
    int event_fd;
    bool dp_running;
};

#endif //ARDP_DP_EVENT_H
