//
// Created by tanchao on 2022/7/1.
//

#ifndef ARDP_DPI_HYPERSCAN_H
#define ARDP_DPI_HYPERSCAN_H

#include "hs.h"
#include "urcu/list.h"
#include "base/config/config.h"
#include "base/bits.h"

typedef enum dpi_sigopt_type_ {
    DPI_SIGOPT_SIG_ID,
    DPI_SIGOPT_NAME,
    DPI_SIGOPT_CONTEXT,
    DPI_SIGOPT_PCRE,
    DPI_SIGOPT_MAX,
} dpi_sigopt_type_t;

enum dpi_sig_context_class_t {
    DPI_SIG_CONTEXT_CLASS_NC = 0,
    DPI_SIG_CONTEXT_CLASS_URI,
    DPI_SIG_CONTEXT_CLASS_HEADER,
    DPI_SIG_CONTEXT_CLASS_BODY,
    DPI_SIG_CONTEXT_CLASS_PACKET,
    DPI_SIG_CONTEXT_CLASS_MAX,
};

typedef struct dpi_hs_summary_ {
    uint32_t db_count;       // number of databases, hyperscan数据库数目
    uint32_t db_bytes;       // total bytes compiled，编译后的大小
    uint32_t scratch_size;   // size of scratch space，内存空间
} dpi_hs_summary_t;

//信号状态表
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

//信号配置结构，代表一个信号包含的信息
typedef struct dpi_sig_config_ {
    char *name, *description, *text;
    uint32_t id;
    uint16_t flags;
    uint8_t severity;                  //严重程度
    uint8_t action;                    //操作
    uint32_t key;
} dpi_sig_config_t;

//一组信号
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

typedef struct dpi_sig_search_api_ {
    void (*init) (void *detector);
    void *(*create) (void);
    void (*add_sig) (void *context, dpi_sig_t *sig);
    void (*compile) (void *context);
    void (*detect) (void *context, void *packet);
    void (*release) (void *context);
} dpi_sig_search_api_t;

typedef struct dpi_sig_search_ {
    uint32_t count;

    void *context;
    dpi_sig_search_api_t *search_api;
} dpi_sig_search_t;

typedef struct dpi_sig_service_tree_ {
    uint32_t count;
    dpi_sig_search_t client_server;
} dpi_sig_service_tree_t;

typedef struct dpi_sig_protocol_tree_ {
    uint32_t count;
    dpi_sig_service_tree_t service_unknown;
} dpi_sig_protocol_tree_t;

typedef struct dpi_sig_detect_tree_ {
    uint32_t count;
    dpi_sig_protocol_tree_t protocol_unknown;
} dpi_sig_detect_tree_t;

typedef struct dpi_detector_ {
    uint32_t pat_count, dpi_act_count;//, eng_count, non_hidden_pat_count;
    dpi_sig_detect_tree_t *tree;
    struct cds_list_head dlpSigList;
    hs_scratch_t *dlp_hs_mpse_build_scratch;     //mpse就是使用了hyperscan作为字符匹配器, hyperscan分配scratch内存
    hs_scratch_t *dlp_hs_mpse_scan_scratch;
    hs_scratch_t *dlp_hs_pcre_build_scratch;     //使用了pcre作为字符匹配器, hyperscan分配scratch内存
    hs_scratch_t *dlp_hs_pcre_scan_scratch;
    dpi_hs_summary_t dlp_pcre_hs_summary;
    dpi_hs_summary_t dlp_hs_summary;
    uint16_t dlp_ref_cnt;
    uint16_t dlp_ver;
    //int def_action;
    uint32_t dlp_apply_dir;
} dpi_detector_t;

typedef struct dpi_sig_node_ {
    struct cds_list_head node;

    dpi_sig_t *sig;
} dpi_sig_node_t;

#define DPI_HS_DETECTION_MAX 0x1000000
typedef struct dlptbl_node_ {
    u_int32_t dlpdet_id : 24,
            dlpat_arr : 8;
} dlptbl_node_t;

typedef struct dlptbl_ {
    dlptbl_node_t *tbl;
} dlptbl_t;

typedef struct dpi_sig_assoc_ {
    dpi_sig_t *sig;
    uint16_t dlptbl_idx;
    uint8_t dpa_mask;
} dpi_sig_assoc_t;

typedef struct dpi_hyperscan_pattern_ {
    char *pattern;
    uint32_t pattern_len;
    uint32_t pattern_idx; /* actual pattern id */
    uint32_t hs_flags;
    dpi_sig_assoc_t hs_sa;
} dpi_hyperscan_pattern_t;

typedef struct dpi_hyperscan_pm_ {
    hs_database_t *db;
    dpi_hyperscan_pattern_t *hs_patterns;
    uint32_t hs_patterns_num; // 表达式的数量
    uint32_t hs_patterns_cap; // allocated capacity
} dpi_hyperscan_pm_t;

typedef struct dpi_hs_class_ {
    dpi_hyperscan_pm_t *hs_pm;
    struct cds_list_head nc_sigs;
} dpi_hs_class_t;

typedef struct dpi_hs_search_ {
    uint32_t count;
    struct dpi_hs_class_ data[DPI_SIG_CONTEXT_CLASS_MAX];

    dlptbl_t *dlptbls;
    dpi_detector_t *detector;
} dpi_hs_search_t;


#endif //ARDP_DPI_HYPERSCAN_H
