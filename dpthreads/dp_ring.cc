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
#include <sys/mman.h>

#include "dp_types.h"
#include "apis.h"
#include "base/helper.h"
#include "base.h"

namespace dpthreads {

    /* 普通帧 */
    #define FRAME_SIZE (1024 * 2)
    #define BLOCK_SIZE (FRAME_SIZE * 4)
    /* 巨型帧 */
    #define JUMBO_FRAME_SIZE (1024*16)
    #define JUMBO_BLOCK_SIZE (JUMBO_FRAME_SIZE * 2)

    #define MAX_TSO_SIZE 65536

    static void dp_tx_flush(dp_context_t *ctx, int limit){
        if (ctx->tx_pending >= limit && ctx->tx_pending > 0) {
            send(ctx->fd, NULL, 0, 0);
            ctx->stats.tx += ctx->tx_pending;
            ctx->tx_pending = 0;
        }
    }

    static int dp_rx(dp_context_t *ctx, uint32_t tick){
        io_ctx_t context;
        uint32_t count = 0;
        dp_ring_t *ring = &ctx->ring;

        context.dp_ctx = ctx;
        context.tick = tick;
        context.stats_slot = g_stats_slot;
        context.tap = ctx->tap;
        context.tc = ctx->tc;
        context.nfq = false;
        mac_cpy(context.ep_mac.ether_addr_octet, ctx->ep_mac.ether_addr_octet);

        while (count < ring->batch){
            struct tpacket_hdr *tp;
            tp = (struct tpacket_hdr *)(ring->rx_map + ring->rx_offset);

            if ((tp->tp_status & TP_STATUS_USER) == 0){
                if (likely(!ctx->tap)){
                    dp_tx_flush(ctx->peer_ctx, 0);
                }
                return count;
            }

            count++;

            if (unlikely(tp->tp_len != tp->tp_snaplen)){
                // 判断是否
                if (tp->tp_status & TP_STATUS_COPY){
                    if (tp->tp_len <= MAX_TSO_SIZE) {
                        int len = recv(ctx->fd, g_tso_packet, MAX_TSO_SIZE, 0);
                    }
                }
            }

        }
    }

    /* 循环缓冲区(ring)的映射和使用 */
    static int dp_ring(int fd, const char *iface, dp_ring_t *ring, bool tap, bool jumboframe, uint blocks, uint batch){
        int enable = 1;
        //丢弃畸形数据包
        setsockopt(fd, SOL_PACKET, PACKET_LOSS, &enable, sizeof(enable));
        setsockopt(fd, SOL_PACKET, PACKET_COPY_THRESH, &enable, sizeof(enable));

        /* 设置环形缓冲区 */
        struct tpacket_req *req =&ring->req;
        //判断是否为巨型帧
        if (!tap && jumboframe){
            req->tp_block_size = JUMBO_BLOCK_SIZE;
            req->tp_frame_size = JUMBO_FRAME_SIZE;
        } else {
            req->tp_block_size = BLOCK_SIZE;
            req->tp_frame_size = FRAME_SIZE;
        }
        req->tp_block_nr = blocks;
        //内存块数量tp_block_nr乘以每个内存块容纳的数据帧数目，应该等于数据包的总数tp_frame_nr
        req->tp_frame_nr = (req->tp_block_size * blocks) / req->tp_frame_size;
        /* calculate memory to mmap in the kernel */
        ring->size = req->tp_block_size * blocks;
        if (!tap) {
            ring->map_size = ring->size * 2;
        } else {
            ring->map_size = ring->size;
        }
        ring->batch = batch;

        /* 为了使用一个套接字来捕获和传输，RX和TX缓冲环的映射必须通过调用mmap来完成 */
        setsockopt(fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req));
        if (!tap) {
            setsockopt(fd, SOL_PACKET, PACKET_TX_RING, req, sizeof(*req));
        }

        /* 建立内存映射，buff指针就已经指向了设置环形缓冲区的开始位置 */
        ring->rx_map = (uint8_t *)mmap(0, ring->map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);

        if (ring->rx_map == MAP_FAILED) {
            printf("fail to mmap (size=0x%x).\n", ring->map_size);
            close(fd);
            return -1;
        }

        ring->tx_map = ring->rx_map + ring->size;
        ring->rx = dp_rx;
        ring->tx = dp_tx;
        ring->stats = dp_stats;
        return fd;
    }

    /* bind port */
    static int dp_ring_bind(int fd, const char *iface){
        struct sockaddr_ll ll;                                /*数据链路层的头信息结构体*/
        memset(&ll, 0, sizeof(ll));
        ll.sll_family = PF_PACKET;                            /*操作链路层的数据*/
        ll.sll_protocol = htons(ETH_P_ALL);                   /*上层协议;16位的主机字节序转换到网络字节序*/
        ll.sll_ifindex = if_nametoindex(iface);        /*接口类型; if_nametoindex检查网卡名称是否有效*/
        ll.sll_hatype = 0;                                    /*报文头类型*/
        ll.sll_pkttype = 0;                                   /*包类型*/
        ll.sll_halen = 0;                                     /*地址长度*/

        return bind(fd, (struct sockaddr *)&ll, sizeof(ll));
    }



    void dp_close_socket(dp_context_t *ctx){
        if (ctx->nfq) {
            if (ctx->nfq_ctx.nfq_q_hdl) {
                nfq_destroy_queue(ctx->nfq_ctx.nfq_q_hdl);
                ctx->nfq_ctx.nfq_q_hdl = NULL;
            }
            if (ctx->nfq_ctx.nfq_hdl) {
                nfq_close(ctx->nfq_ctx.nfq_hdl);
                ctx->nfq_ctx.nfq_hdl = NULL;
            }
        } else {
            munmap(ctx->ring.rx_map, ctx->ring.map_size);
            close(ctx->fd);
        }
    }

    /* 接收本机网卡下的数据帧或者数据包，常用来监听和分析网络流量，常见的方式有以下2种
     * socket(AF_INET, SOCK_RAW, IPPROTO_TCP|IPPROTO_UDP|IPPROTO_ICMP)发送接收ip数据包，不能用IPPROTO_IP，因为如果是用了IPPROTO_IP，系统根本就不知道该用什么协议。
     * socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP|ETH_P_ARP|ETH_P_ALL))发送接收以太网数据帧
     * */
    int dp_open_socket(dp_context_t *ctx, const char *iface, bool tap, bool jumboframe, uint blocks, uint batch){
        //AF_PACKET 与 SOCK_RAW 套接字一起使用接收包含14字节以太网报头的数据报
        //建立链路层socket, AF_PACKET地址族
        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0){
            printf("fail to open socket.\n");
            return -1;
        }

        int err = 0;
        err = dp_ring(fd, iface, &ctx->ring, tap, jumboframe, blocks, batch);
        if (err < 0) {
            close(fd);
            return -1;
        }

        err = dp_ring_bind(fd, iface);
        if (err < 0) {
            printf("fail to bind socket.\n");
            dp_close_socket(ctx);
            return -1;
        }

        return fd;
    }


}