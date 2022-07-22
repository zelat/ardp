//
// Created by tanchao on 2022/6/29.
//
#include <iostream>
#include "test_dpi_hs_search.h"
#include "dpi_search.h"

void test_dpi_hs_search::ActivateScratch(hs_scratch_t **build_scratch,
                                         hs_scratch_t **scan_scratch) {
    hs_free_scratch(*scan_scratch);
    *scan_scratch = *build_scratch;
    *build_scratch = NULL;
}

void test_dpi_hs_search::HyperscanActivate() {
    ActivateScratch(&detector->dlp_hs_mpse_build_scratch, &detector->dlp_hs_mpse_scan_scratch);
    ActivateScratch(&detector->dlp_hs_pcre_build_scratch, &detector->dlp_hs_pcre_scan_scratch);
}

void test_dpi_hs_search::HyperscanActivateMpse() {
    ActivateScratch(&detector->dlp_hs_mpse_build_scratch, &detector->dlp_hs_mpse_scan_scratch);
}

void test_dpi_hs_search::HyperscanActivatePcre() {
    ActivateScratch(&detector->dlp_hs_pcre_build_scratch, &detector->dlp_hs_pcre_scan_scratch);
}

dpi_hyperscan_pm_t *test_dpi_hs_search::dpi_hs_create() {
    //给huperscan pattern分配内存块
    auto *pm = new dpi_hyperscan_pm_t[1];

    if (!pm) {
        cout << "Unable to allocate memory for hyperscan pattern match!" << endl;
        return NULL;
    }
    pm->hs_patterns_cap = INITIAL_PATTERN_ARRAY_ALLOC_SIZE;
    //给hyperscan模式匹配签名分配内存块
    pm->hs_patterns = (dpi_hyperscan_pattern_t *)calloc(1, sizeof(dpi_hyperscan_pattern_t) * pm->hs_patterns_cap);
    if (!pm->hs_patterns) {
        cout << "Unable to allocate memory for hyperscan pattern match sigature!" << endl;
        delete(pm);
        return NULL;
    }
    return pm;
}

int dpi_dlp_hs_compile(dpi_hyperscan_pm_t *hspm, dpi_detector_t *detector) {

    if (!hspm || hspm->hs_patterns_num == 0) {
        return -1;
    }

    // The Hyperscan compiler takes its patterns in a group of arrays.
    uint32_t num_patterns;
    char **patterns;
    uint32_t *flags;
    uint32_t *ids;
    uint32_t i;

    num_patterns = hspm->hs_patterns_num;
    patterns = (char **)calloc(num_patterns, sizeof(char *));
    if (!patterns) {
        cout << "Out of memory, patterns cannot be allocated!" << endl;
//        DEBUG_ERROR(DBG_DETECT, "Out of memory, patterns cannot be allocated!\n");
        return -1;
    }

    flags = (uint32_t *)calloc(num_patterns, sizeof(uint32_t));
    if (!flags) {
        cout << "Out of memory, flags cannot be allocated!" << endl;
//        DEBUG_ERROR(DBG_DETECT, "Out of memory, flags cannot be allocated!\n");
        free(patterns);
        return -1;
    }

    ids = (uint32_t *)calloc(num_patterns, sizeof(uint32_t));
    if (!ids) {
        cout << "Out of memory, flags cannot be allocated!" << endl;
//        DEBUG_ERROR(DBG_DETECT, "Out of memory, ids cannot be allocated!\n");
        free(patterns);
        free(flags);
        return -1;
    }

    for (i=0; i < num_patterns; i++) {
        dpi_hyperscan_pattern_t *hp = &hspm->hs_patterns[i];
        patterns[i] = hp->pattern;
        flags[i] = hp->hs_flags;
        flags[i] |= HS_FLAG_SINGLEMATCH;
        ids[i] = i;
    }

    hs_compile_error_t *compile_error = NULL;
    hs_error_t error = hs_compile_multi((const char **)patterns, flags, ids, num_patterns, HS_MODE_BLOCK, NULL, &(hspm->db), &compile_error);

    free(patterns);
    free(flags);
    free(ids);

    if (compile_error != NULL) {
        cout << "hs_compile_multi() failed: " << compile_error->message <<  " (expression: " << compile_error->expression << ")" << endl;
//        DEBUG_ERROR(DBG_DETECT,"hs_compile_multi() failed: %s (expression: %d)\n",
//                    compile_error->message, compile_error->expression);
        hs_free_compile_error(compile_error);
        return -1;
    }

    if (error != HS_SUCCESS) {
        cout << "hs_compile_multi() failed: error " << error << endl;
//        DEBUG_ERROR(DBG_DETECT,"hs_compile_multi() failed: error %d\n", error);
        return -1;
    }

    // Ensure the per detector Hyperscan scratch space has seen this database.
    error = hs_alloc_scratch(hspm->db, &detector->dlp_hs_mpse_build_scratch);

    if (error != HS_SUCCESS) {
        cout << "hs_alloc_scratch() failed: error " << error << endl;
//        DEBUG_ERROR(DBG_DETECT,"hs_alloc_scratch() failed: error %d\n", error);
        return -1;
    }

    uint32_t scratch_size = 0;
    error = hs_scratch_size(detector->dlp_hs_mpse_build_scratch, (size_t *)&scratch_size);
    if (error != HS_SUCCESS) {
        cout << "hs_scratch_size() failed: error " << error << endl;
//        DEBUG_ERROR(DBG_DETECT,"hs_scratch_size() failed: error %d\n", error);
        return -1;
    }

    uint32_t db_size = 0;
    error = hs_database_size(hspm->db, (size_t *)&db_size);
    if (error != HS_SUCCESS) {
        cout << "hs_database_size() failed: error " << error << endl;
//        DEBUG_ERROR(DBG_DETECT,"hs_database_size() failed: error %d\n", error);
        return -1;
    }

    //DEBUG_LOG(DBG_DETECT,NULL, "Built Hyperscan database: %u patterns, %u bytes\n",
    //                        num_patterns, db_size);

    // Update summary info.
    detector->dlp_hs_summary.db_count++;
    detector->dlp_hs_summary.db_bytes += db_size;
    detector->dlp_hs_summary.scratch_size = scratch_size;

    //DEBUG_LOG(DBG_DETECT, NULL, "Total (%d) hyperscan db allocated, db_bytes(%u), scratch_size(%u)!\n",
    //detector->dlp_hs_summary.db_count, detector->dlp_hs_summary.db_bytes, detector->dlp_hs_summary.scratch_size);
    return 0;
}


// ---------------------------------------------------------------------------------------------------------------------
//初始化
test_dpi_hs_search::test_dpi_hs_search(dpi_detector_t *dt, dpi_hs_search_t *hsSearch)
        : detector(dt), hs_search(hsSearch) {
//    DEBUG_LOG_FUNC_ENTRY(DBG_INIT|DBG_DETECT,NULL);
    HyperscanActivate();
}

//创建hyperscan pattern规则库
dpi_hs_search_t *test_dpi_hs_search::dpi_dlp_hs_search_create() {
//    dpi_hs_search_t *hs_search = calloc(1, sizeof(dpi_hs_search_t));
    auto *hs_search = new dpi_hs_search_t[1];
    if (hs_search != nullptr) {
        for (int dpi_sig_context_class_t = DPI_SIG_CONTEXT_CLASS_NC;
             dpi_sig_context_class_t < DPI_SIG_CONTEXT_CLASS_MAX; dpi_sig_context_class_t++) {
            hs_search->data[dpi_sig_context_class_t].hs_pm = dpi_hs_create();
            CDS_INIT_LIST_HEAD(&hs_search->data[dpi_sig_context_class_t].nc_sigs);
        }
    }

    return hs_search;
}

void test_dpi_hs_search::dpi_dlp_hs_search_add_dlprule(dpi_sig_t *sig) {
    return;
}


void test_dpi_hs_search::dpi_dlp_hs_search_compile() {
    dpi_sig_context_class_t c;
    int i, j;

    hs_search->dlptbls = new dlptbl_t[MAX_DP_THREADS];
    if (hs_search->dlptbls == NULL) {
        return;
    }

    for (int i = 0; i < MAX_DP_THREADS; ++i) {
        hs_search->dlptbls[i].tbl = new dlptbl_node_t[hs_search->count];
        if (hs_search->dlptbls[i].tbl == NULL){
            for (int j = i -1; j >= 0; ++j) {
                delete(hs_search->dlptbls[j].tbl);
            }
            break;
        }
    }
    for (int c = 0; c < DPI_SIG_CONTEXT_CLASS_MAX; ++c) {
        dpi_dlp_hs_compile(hs_search->data[c].hs_pm, hs_search->detector);
    }
}


