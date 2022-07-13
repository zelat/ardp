//
// Created by Administrator on 2022/7/13.
//

#include <iostream>
#include <cstring>
#include "dp_ctrl_internal_net.h"

namespace dpthreads {
//    dpthreads::DP_CTRL_Internal_Net::DP_CTRL_Internal_Net() {
//        g_internal_subnet4 = nullptr;
//        g_policy_addr = nullptr;
//    }
//
//    dpthreads::DP_CTRL_Internal_Net::~DP_CTRL_Internal_Net() {
//
//    }

    int DP_CTRL_Internal_Net::Init(json_t *msg, bool internal) {
        int count;
        int flag;
        json_t *sa, *c_sa;
        io_internal_subnet4_t *subnet4, *tsubnet4;
        static io_internal_subnet4_t *t_internal_subnet4 = NULL;

        flag = json_integer_value(json_object_get(msg, "flag"));
        sa = json_object_get(msg, "subnet_addr");
        count = json_array_size(sa);

        //给所有subnets分配一块连续的内存区
        subnet4 = (io_internal_subnet4_t *)calloc(sizeof(io_internal_subnet4_t) + count * sizeof(io_subnet4_t), 1);
        if (!subnet4){
            std::cout << "Out of memory!" << std::endl;
        }

        //将agent发送过来的json数据转化成C结构
        subnet4->count = count;
        for (int i =0; i < count; i++) {
            c_sa = json_array_get(sa, i);
            subnet4->list[i].ip = inet_addr(json_string_value(json_object_get(c_sa, "ip")));
            subnet4->list[i].mask = inet_addr(json_string_value(json_object_get(c_sa, "mask")));
        }

        if (flag & MSG_START){
            t_internal_subnet4 = subnet4;
        } else {
            if (!t_internal_subnet4) {
                if (internal) {
                    std::cout << "missed internal ip msg start!" << std::endl;
                } else {
                    std::cout << "missed policy addr msg start!" << std::endl;
                }
                return -1;
            }
            tsubnet4 = (io_internal_subnet4_t *)calloc(sizeof(io_internal_subnet4_t) + (t_internal_subnet4->count + count) * sizeof(io_subnet4_t), 1);
            if (!tsubnet4) {
                std::cout << "out of memory!!" << std::endl;
                return -1;
            }

            memcpy(&tsubnet4->list[0], &t_internal_subnet4->list[0], sizeof(io_subnet4_t) * t_internal_subnet4->count);
            memcpy(&tsubnet4->list[t_internal_subnet4->count], &subnet4->list[0], sizeof(io_subnet4_t) * subnet4->count);
            tsubnet4->count = t_internal_subnet4->count + count;
            free(subnet4);
            free(t_internal_subnet4);
            t_internal_subnet4 = tsubnet4;
        }


        if (!(flag & MSG_END)) {
            return 0;
        }

//        if (internal) {
//            old = g_internal_subnet4;
//        } else {
//            old = g_policy_addr;
//        }
//        if (multiple_msg) {
//            if (internal) {
//                g_internal_subnet4 = tsubnet4;
//            } else {
//                g_policy_addr = tsubnet4;
//            }
//        } else {
//            if (internal) {
//                g_internal_subnet4 = subnet4;
//            } else {
//                g_policy_addr = subnet4;
//            }
//        }
//
//        synchronize_rcu();
//
//        free(old);

        return 0;
    }

}