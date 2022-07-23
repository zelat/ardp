//
// Created by Administrator on 2022/7/23.
//

#ifndef ARDP_DPI_PARSER_H
#define ARDP_DPI_PARSER_H

#include "dpi/dpi_packet.h"

void *dpi_get_parser_data(dpi_packet_t *p);
void dpi_put_parser_data(dpi_packet_t *p, void *data);
void dpi_purge_parser_data(dpi_session_t *s);
void dpi_hire_parser(dpi_packet_t *p);
void dpi_fire_parser(dpi_packet_t *p);
void dpi_ignore_parser(dpi_packet_t *p);
void dpi_set_asm_seq(dpi_packet_t *p, uint32_t seq);
bool dpi_is_parser_final(dpi_packet_t *p);
void dpi_finalize_parser(dpi_packet_t *p);
void dpi_recruit_parser(dpi_packet_t *p);
void dpi_midstream_recruit_parser(dpi_packet_t *p);
void dpi_proto_parser(dpi_packet_t *p);
void dpi_midstream_proto_praser(dpi_packet_t *p);

#endif //ARDP_DPI_PARSER_H
