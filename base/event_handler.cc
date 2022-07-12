//
// Created by tanchao on 2022/7/12.
//
#include <sys/epoll.h>
#include <errno.h>
#include <vector>
#include <unistd.h>
#include <string.h>
#include <base/config/config.h>
#include <cstdio>
#include "event_handler.h"

#define EVENT_MAX 10
namespace base {
    EventHandler::EventHandler(){
        _run = false;
        event_fd = AGENT_FAILED;
    }

    EventHandler::~EventHandler(){
        Exit();
    }

    int EventHandler::Init(){
        event_fd = epoll_create1(EPOLL_CLOEXEC);
        if(event_fd == -1)
        {
            return AGENT_FAILED;
        }
        return AGENT_SUCCESS;
    }

    void EventHandler::Exit(){

        if(_run) { _run = false; }
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
            printf("EventHandler", "Add event node failed, %s", strerror(errno));
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
            printf("EventHandler", "Remove event node failed, %s", strerror(errno));
            return AGENT_FAILED;
        }
        return AGENT_SUCCESS;

    }

    void EventHandler::Run(){
        std::vector<struct epoll_event> events;

        events.resize(EVENT_MAX);
        _run = true;
        while(_run)
        {
            int nfds = epoll_wait(event_fd, &events[0], EVENT_MAX, -1);
            if(nfds == -1)
            {
                printf("EventHandler", "epoll wait request error, %s", strerror(errno));
                // ignore interrupt.
                //if(errno == EINTR) continue;
                //_run = false;
                continue;
            }
            for(int i = 0; i < nfds; i++)
            {
                static_cast<EventNode *>(events[i].data.ptr)->OnEventReceived();

            }
        }
    }
}