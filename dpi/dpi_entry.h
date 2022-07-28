//
// Created by Administrator on 2022/7/27.
//

#ifndef ARDP_DPI_ENTRY_H
#define ARDP_DPI_ENTRY_H

#include "apis.h"

void dpi_setup(io_callback_t *cb, io_config_t *cfg);
void dpi_init(int reason);
int dpi_recv_packet(io_ctx_t *context, uint8_t *pkt, int len);
void dpi_timeout(uint32_t tick);

#endif //ARDP_DPI_ENTRY_H
