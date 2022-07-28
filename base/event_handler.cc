//
// Created by tanchao on 2022/7/12.
//
#include <sys/epoll.h>
#include <errno.h>
#include <vector>
#include <unistd.h>
#include <string.h>
#include <cstdio>
#include "event_handler.h"
#include "base.h"
#ifdef __cplusplus
extern "C"
{
#endif
#include "debug.h"
#ifdef __cplusplus
}
#endif

#define MAX_EPOLL_EVENTS 128
#define AGENT_SUCCESS 0
#define AGENT_FAILED -1

namespace base {
    EventHandler::EventHandler(){
        g_running = false;
        event_fd = AGENT_FAILED;
    }

    EventHandler::~EventHandler(){
        Exit();
    }

    int EventHandler::Init(){
        event_fd = epoll_create1(EPOLL_CLOEXEC);
        if(event_fd == -1){
            return AGENT_FAILED;
        }
        return AGENT_SUCCESS;
    }

    void EventHandler::Exit(){

        if(g_running) { g_running = false; }
        if(event_fd != AGENT_FAILED) { close(event_fd); }
    }

    int EventHandler::AddEventNode(EventNode *node){
        struct epoll_event ev;
        int ret;

        if(node == NULL) { return AGENT_FAILED; }
        if(event_fd == -1) { return AGENT_FAILED; }
        if(node->GetEventFd() == -1) { return AGENT_FAILED; }

        ev.events = node->GetEventType();
        ev.data.ptr = node;

        ret = epoll_ctl(event_fd, EPOLL_CTL_ADD, node->GetEventFd(), &ev);
        if(ret == -1)
        {
            DEBUG_INIT("Add event node failed, %s", strerror(errno));
            return AGENT_FAILED;
        }
        return AGENT_SUCCESS;
    }

    int EventHandler::RemoveEventNode(EventNode *node){
        struct epoll_event ev;
        int ret;

        if(node == NULL) { return AGENT_FAILED; }
        if(event_fd == -1) { return AGENT_FAILED; }
        if(node->GetEventFd() == -1) { return AGENT_FAILED; }

        ev.events = node->GetEventType();
        ev.data.ptr = node;

        ret = epoll_ctl(event_fd, EPOLL_CTL_DEL, node->GetEventFd(), &ev);
        if(ret == -1)
        {
            DEBUG_INIT("Remove event node failed, %s", strerror(errno));
            return AGENT_FAILED;
        }
        return AGENT_SUCCESS;

    }

    void EventHandler::Run(){
        std::vector<struct epoll_event> events;

        events.resize(MAX_EPOLL_EVENTS);
        g_running = true;
        while(g_running)
        {
            int nfds = epoll_wait(event_fd, &events[0], MAX_EPOLL_EVENTS, -1);
            if(nfds == -1)
            {
                DEBUG_INIT("epoll wait request error, %s", strerror(errno));
                continue;
            }
            for(int i = 0; i < nfds; i++)
            {
                static_cast<EventNode *>(events[i].data.ptr)->OnEventReceived();
            }
        }
    }

    int EventHandler::GetEventFD() {
        return event_fd;
    }
}