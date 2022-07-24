//
// Created by tanchao on 2022/7/23.
//

#ifndef ARDP_DPI_PARSER_H
#define ARDP_DPI_PARSER_H

#include "dpi/dpi_packet.h"

void dpi_purge_parser_data(dpi_session_t *s);
void dpi_finalize_parser(dpi_packet_t *p);
void dpi_recruit_parser(dpi_packet_t *p);
void dpi_midstream_recruit_parser(dpi_packet_t *p);
void dpi_proto_parser(dpi_packet_t *p);
void dpi_midstream_proto_praser(dpi_packet_t *p);

// Called by protocol parser
inline void *dpi_get_parser_data(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    return s->parser_data[p->cur_parser->type];
}

inline void dpi_put_parser_data(dpi_packet_t *p, void *data)
{
    dpi_session_t *s = p->session;
    s->parser_data[p->cur_parser->type] = data;
}

// Called by protocol parser
inline void dpi_hire_parser(dpi_packet_t *p)
{
    DEBUG_LOG(DBG_PARSER, p, "%s\n", p->cur_parser->name);

    dpi_session_t *s = p->session;
    BITMASK_SET(s->parser_bits, p->cur_parser->type);
}

inline void dpi_fire_parser(dpi_packet_t *p)
{
    DEBUG_LOG(DBG_PARSER, p, "%s\n", p->cur_parser->name);

    dpi_session_t *s = p->session;
    BITMASK_UNSET(s->parser_bits, p->cur_parser->type);
}

// It's intentional to keep this as a separate function from 'fire'.
// 'ignore' is used in the case where the session type is finalized,
// but the parser won't be at work.
inline void dpi_ignore_parser(dpi_packet_t *p)
{
    DEBUG_LOG(DBG_PARSER, p, "%s\n", p->cur_parser->name);

    dpi_session_t *s = p->session;
    BITMASK_UNSET(s->parser_bits, p->cur_parser->type);
}

inline void dpi_set_asm_seq(dpi_packet_t *p, uint32_t seq)
{
    p->parser_asm_seq = seq;
}

inline bool dpi_is_parser_final(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    return !!(s->flags & DPI_SESS_FLAG_FINAL_PARSER);
}
#endif //ARDP_DPI_PARSER_H
