//
// Created by Administrator on 2022/7/20.
//

#ifndef ARDP_DPI_SIG_H
#define ARDP_DPI_SIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include "dpi_hyperscan.h"

namespace dpi {

    typedef enum dpi_sig_context_type_ {
        DPI_SIG_CONTEXT_TYPE_URI_ORIGIN = 0,
        DPI_SIG_CONTEXT_TYPE_HEADER,
        DPI_SIG_CONTEXT_TYPE_BODY,
        DPI_SIG_CONTEXT_TYPE_SQL_QUERY,
        DPI_SIG_CONTEXT_TYPE_PACKET_ORIGIN,
        DPI_SIG_CONTEXT_TYPE_MAX,
    } dpi_sig_context_type_t;

    typedef struct dpi_sig_user_ {
        uint16_t flags;
        uint8_t action;
        uint8_t severity;

        dpi_sig_t *sig;
    } dpi_sig_user_t;
}

#endif //ARDP_DPI_SIG_H
