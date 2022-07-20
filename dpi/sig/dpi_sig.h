//
// Created by Administrator on 2022/7/20.
//

#ifndef ARDP_DPI_SIG_H
#define ARDP_DPI_SIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include "dpi_hyperscan.h"
#include <pcre2.h>

namespace dpi {
    #define PCRE2_CODE_UNIT_WIDTH 8
    #define DPI_SIG_MIN_USER_SIG_ID 20000
    #define DPI_SIG_MAX_USER_SIG_ID 29999
    #define DPI_SIG_MIN_PRE_USER_SIG_ID 30000
    #define DPI_SIG_MAX_PRE_USER_SIG_ID 39999
    #define DPI_SIG_MIN_WAF_SIG_ID 40000
    #define DPI_SIG_MAX_WAF_SIG_ID 49999

    typedef enum dpi_sigopt_type_ {
        DPI_SIGOPT_SIG_ID,
        DPI_SIGOPT_NAME,
        DPI_SIGOPT_CONTEXT,
        DPI_SIGOPT_PCRE,
        DPI_SIGOPT_MAX,
        } dpi_sigopt_type_t;

    typedef enum dpi_sig_context_class_ {
        DPI_SIG_CONTEXT_CLASS_NC = 0,
        DPI_SIG_CONTEXT_CLASS_URI,
        DPI_SIG_CONTEXT_CLASS_HEADER,
        DPI_SIG_CONTEXT_CLASS_BODY,
        DPI_SIG_CONTEXT_CLASS_PACKET,
        DPI_SIG_CONTEXT_CLASS_MAX,
        } dpi_sig_context_class_t;

    typedef enum dpi_sig_context_type_ {
        DPI_SIG_CONTEXT_TYPE_URI_ORIGIN = 0,
        DPI_SIG_CONTEXT_TYPE_HEADER,
        DPI_SIG_CONTEXT_TYPE_BODY,
        DPI_SIG_CONTEXT_TYPE_SQL_QUERY,
        DPI_SIG_CONTEXT_TYPE_PACKET_ORIGIN,
        DPI_SIG_CONTEXT_TYPE_MAX,
        } dpi_sig_context_type_t;

#define DPI_MAX_PCRE_PATTERNS 16

    typedef enum dpi_action_cate_ {
        DPI_CAT_NONE = 0,
        DPI_CAT_DETECTION,
        DPI_CAT_BYPASS,
        DPI_CAT_PREVENTION,
        } dpi_action_cate_t;

#define DPI_SIGOPT_PAT_FLAG_NEGATIVE      0x01
#define DPI_SIGOPT_PAT_FLAG_NO_CASE       0x02
#define DPI_SIGOPT_PAT_FLAG_PCRE          0x04
#define DPI_SIGOPT_PAT_FLAG_RAW           0x08
#define DPI_SIGOPT_PAT_FLAG_REVERSE       0x10
#define DPI_SIGOPT_PAT_FLAG_LINE_DIGIT    0x20
#define DPI_SIGOPT_PAT_FLAG_CONTEXT_INUSE 0x40

    typedef struct dpi_sig_macro_sig_ {
        struct cds_list_head node;

        dpi_sig_config_t conf;
        struct cds_list_head sigs;
    } dpi_sig_macro_sig_t;

    // forward declaration
    struct dpi_sigopt_node_;
    struct dpi_sig_user_;

    typedef struct dpi_sig_ {
        struct cds_list_head node;

        dpi_sig_config_t *conf;
        dpi_sig_macro_sig_t *macro;
        void *detector;

        uint32_t sig_id;
        uint16_t action   : 3,
        severity : 3,
        hs_count: 5;

        uint16_t flags;
        struct dpi_sigopt_node_ *hs_pats[DPI_MAX_PCRE_PATTERNS];

        struct cds_list_head uri_opts, header_opts, body_opts, packet_opts;
        BITMASK_DEFINE(opt_inuse, DPI_SIGOPT_MAX);
        BITMASK_DEFINE(pat_inuse, DPI_SIG_CONTEXT_CLASS_MAX);

        uint8_t pcre_count;
        void *last_pattern;
    } dpi_sig_t;

    typedef struct dpi_sig_user_ {
        uint16_t flags;
        uint8_t action;
        uint8_t severity;

        dpi_sig_t *sig;
    } dpi_sig_user_t;

    typedef struct dpi_sig_user_link_ {
        struct cds_list_head node;
        dpi_sig_user_t *sig_user;
    } dpi_sig_user_link_t;

    // forward declaration
    struct dpi_packet_;

    typedef struct dpi_sigopt_api_ {
        dpi_sigopt_type_t type;
        void *value;
        dpi_sigopt_status_t (*parser) (char *value, dpi_sig_t *sig);
        int (*handler) (void *context, struct dpi_packet_ *pkt, dpi_sig_t *sig);
        void (*dump) (void *context);
        void (*release) (void *context);
    } dpi_sigopt_api_t;

    typedef struct dpi_sigopt_node_ {
        struct cds_list_head node;
        dpi_sigopt_api_t *sigapi;
    } dpi_sigopt_node_t;

    typedef struct dpi_sigopt_reg_ {
        struct cds_list_head sonode;
        const char *soname;
        dpi_sigopt_api_t soapi;
    } dpi_sigopt_reg_t;

    typedef struct dpi_dlp_parser_ {
        struct cds_list_head dlprulelist;
        dpi_sigopt_status_t (*parse_dlpopts) (struct dpi_dlp_parser_ *sigparser, char **sigopts, int sigcount,
                dpi_sig_t *sig, void *detector);
    } dpi_dlp_parser_t;

    typedef struct dpi_sig_search_api_ {
        void (*init) (void *detector);
        void *(*create) (void);
        void (*add_sig) (void *context, dpi_sig_t *sig);
        void (*compile) (void *context);
        void (*detect) (void *context, void *packet);
        void (*release) (void *context);
    } dpi_sig_search_api_t;

    typedef struct dpi_sigopt_pcre_pattern_ {
        dpi_sigopt_node_t node;

        uint8_t flags;
        uint8_t class;  //dpi_sig_context_class_t
        uint8_t type;  //dpi_sig_context_type_t

        struct {
            uint8_t *string;           /*pcre signature*/
            pcre2_code *recompiled;    /*pcre compiled database*/
            struct hs_database *hs_db; /* hyperscan database */
            int hs_flags;              /* hyperscan flags used for compile */
            int hs_noconfirm;          /* hyperscan matches don't need confirm */
        } pcre;
    } dpi_sigopt_pcre_pattern_t;
}

#endif //ARDP_DPI_SIG_H
