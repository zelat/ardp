//
// Created by tanchao on 2022/7/14.
//
#include <cstring>
#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>                                        /*在Linux上*/
#include <cstdio>
#include <unistd.h>

namespace dpthreads {

//    static int dp_ring_v1(int fd, const char *iface, dp_ring_t *ring, bool tap, bool jumboframe, uint blocks, uint batch){
//        int enable = 1;
//        //丢弃畸形数据包
//        setsockopt(fd, SOL_PACKET, PACKET_LOSS, &enable, sizeof(enable));
//    }

    static int dp_ring_bind(int fd, const char *iface){
        struct sockaddr_ll ll;                                /*数据链路层的头信息结构体*/
        memset(&ll, 0, sizeof(ll));
        ll.sll_family = PF_PACKET;                            /*操作链路层的数据*/
        ll.sll_protocol = htons(ETH_P_ALL);                   /*上层协议;16位的主机字节序转换到网络字节序*/
        ll.sll_ifindex = if_nametoindex(iface);               /*接口类型; if_nametoindex检查网卡名称是否有效*/
        ll.sll_hatype = 0;                                    /*报文头类型*/
        ll.sll_pkttype = 0;                                   /*包类型*/
        ll.sll_halen = 0;                                     /*地址长度*/

        return bind(fd, (struct sockaddr *)&ll, sizeof(ll));
    }

    /* 接收本机网卡下的数据帧或者数据包，常用来监听和分析网络流量，常见的方式有以下2种
     * socket(AF_INET, SOCK_RAW, IPPROTO_TCP|IPPROTO_UDP|IPPROTO_ICMP)发送接收ip数据包，不能用IPPROTO_IP，因为如果是用了IPPROTO_IP，系统根本就不知道该用什么协议。
     * socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP|ETH_P_ARP|ETH_P_ALL))发送接收以太网数据帧
     * */
//    int dp_open_socket(dp_context_t *ctx, const char *iface, bool tap, bool jumboframe, uint blocks, uint batch){
//        //AF_PACKET 与 SOCK_RAW 套接字一起使用接收包含14字节以太网报头的数据报
//        //建立链路层socket
//        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
//        if (fd < 0){
//            printf("fail to open socket.\n");
//            return -1;
//        }
//
//        int err = 0;
//        err = dp_ring_v1(fd, iface, &ctx->ring, tap, jumboframe, blocks, batch);
//        if (err < 0) {
//            close(fd);
//            return -1;
//        }
//
//        err = dp_ring_bind(fd, iface);
//        if (err < 0) {
//            printf("fail to bind socket.\n");
//            dp_close_socket(ctx);
//            return -1;
//        }
//
//        return fd;
//    }
}