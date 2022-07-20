//
// Created by Administrator on 2022/7/20.
//

#ifndef ARDP_DP_RING_H
#define ARDP_DP_RING_H

namespace dpthreads {
    /* 普通帧 */
    #define FRAME_SIZE (1024 * 2)
    #define BLOCK_SIZE (FRAME_SIZE * 4)
    /* 支持巨型帧 */
    #define JUMBO_FRAME_SIZE (1024*16)
    #define JUMBO_BLOCK_SIZE (JUMBO_FRAME_SIZE * 2)
    #define MAX_TSO_SIZE 65536

    static uint8_t g_tso_packet[MAX_TSO_SIZE];

    class DP_Ring {
    private:
        static void dp_tx_flush(dp_context_t *ctx, int limit);
        static int dp_tx(dp_context_t *ctx, uint8_t *pkt, int len, bool large_frame);
        static int dp_rx(dp_context_t *ctx, uint32_t tick);
        static void dp_stats(int fd, dp_stats_t *stats);
        int dp_ring(int fd, const char *iface, dp_ring_t *ring, bool tap, bool jumboframe, uint blocks, uint batch);
        int dp_ring_bind(int fd, const char *iface);
    public:
        DP_Ring();
        int dp_open_socket(dp_context_t *ctx, const char *iface, bool tap, bool jumboframe, uint blocks, uint batch);
        void dp_close_socket(dp_context_t *ctx);
    };
}
#endif //ARDP_DP_RING_H
