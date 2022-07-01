//
// Created by tanchao on 2022/7/1.
//

#ifndef ARDP_DPI_HYPERSCAN_H
#define ARDP_DPI_HYPERSCAN_H

#include "hs.h"
#include "urcu/list.h"
#include "config.h"
#include "utils/bits.h"

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

typedef struct dpi_hs_summary_ {
    int db_count;       // number of databases
    int db_bytes;       // total bytes compiled
    int scratch_size;   // size of scratch space
} dpi_hs_summary_t;

typedef enum dpi_sigopt_status_ {
    DPI_SIGOPT_OK = 0,
    DPI_SIGOPT_FAILED,
    DPI_SIGOPT_INVALID_SIG_NAME,
    DPI_SIGOPT_UNKNOWN_OPTION,
    DPI_SIGOPT_MISSING_OPTION,
    DPI_SIGOPT_DUP_OPTION,
    DPI_SIGOPT_INVALID_OPTION_VALUE,
    DPI_SIGOPT_VALUE_TOO_LONG,
    DPI_SIGOPT_TOO_MANY_DLP_RULE,
    DPI_SIGOPT_INVALID_USER_SIG_ID,
    DPI_SIGOPT_TOO_MANY_PCRE_PAT,
} dpi_sigopt_status_t;

typedef struct dpi_sig_config_ {
    char *name, *description, *text;
    uint32_t id;
    uint16_t flags;
    uint8_t severity;
    uint8_t action;
    uint32_t key;
} dpi_sig_config_t;

typedef struct dpi_sig_macro_sig_ {
    struct cds_list_head node;
    dpi_sig_config_t conf;
    struct cds_list_head sigs;
} dpi_sig_macro_sig_t;

typedef struct dpi_sig_ {
    struct cds_list_head node;

    dpi_sig_config_t *conf;
    dpi_sig_macro_sig_t *macro;
    void *detector;

    int sig_id;
    short int action   : 3,
              severity : 3,
              hs_count: 5;

    short int flags;
    struct dpi_sigopt_node_ *hs_pats[DPI_MAX_PCRE_PATTERNS];

    struct cds_list_head uri_opts, header_opts, body_opts, packet_opts;
    BITMASK_DEFINE(opt_inuse, DPI_SIGOPT_MAX);
    BITMASK_DEFINE(pat_inuse, DPI_SIG_CONTEXT_CLASS_MAX);

    uint8_t pcre_count;
    void *last_pattern;
} dpi_sig_t;

typedef struct dpi_sig_search_api_ {
    void (*init) (void *detector);
    void *(*create) (void);
    void (*add_sig) (void *context, dpi_sig_t *sig);
    void (*compile) (void *context);
    void (*detect) (void *context, void *packet);
    void (*release) (void *context);
} dpi_sig_search_api_t;

typedef struct dpi_sig_search_ {
    int count;

    void *context;
    dpi_sig_search_api_t *search_api;
} dpi_sig_search_t;

typedef struct dpi_sig_service_tree_ {
    int count;
    dpi_sig_search_t client_server;
} dpi_sig_service_tree_t;

typedef struct dpi_sig_protocol_tree_ {
    int count;
    dpi_sig_service_tree_t service_unknown;
} dpi_sig_protocol_tree_t;

typedef struct dpi_sig_detect_tree_ {
    int count;
    dpi_sig_protocol_tree_t protocol_unknown;
} dpi_sig_detect_tree_t;

typedef struct dpi_detector_ {
    int pat_count, dpi_act_count;//, eng_count, non_hidden_pat_count;
    dpi_sig_detect_tree_t *tree;
    struct cds_list_head dlpSigList;
    hs_scratch_t *dlp_hs_mpse_build_scratch;     //mpse就是使用了hyperscan作为字符匹配器, hyperscan分配scratch内存
    hs_scratch_t *dlp_hs_mpse_scan_scratch;
    hs_scratch_t *dlp_hs_pcre_build_scratch;     //使用了pcre作为字符匹配器, hyperscan分配scratch内存
    hs_scratch_t *dlp_hs_pcre_scan_scratch;
    dpi_hs_summary_t dlp_pcre_hs_summary;
    dpi_hs_summary_t dlp_hs_summary;
    short int dlp_ref_cnt;
    short int dlp_ver;
    //int def_action;
    int dlp_apply_dir;
} dpi_detector_t;

typedef struct dpi_hyperscan_pattern_ {
    char *pattern;
    int pattern_len;
    int pattern_idx; /* actual pattern id */
    int hs_flags;
    int hs_sa;
} dpi_hyperscan_pattern_t;

typedef struct dpi_hyperscan_pm_ {
    hs_database_t *db;
    dpi_hyperscan_pattern_t *hs_patterns;
    int hs_patterns_num; // 表达式的数量
    int hs_patterns_cap; // allocated capacity
} dpi_hyperscan_pm_t;
#endif //ARDP_DPI_HYPERSCAN_H
