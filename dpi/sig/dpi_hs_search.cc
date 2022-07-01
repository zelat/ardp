//
// Created by tanchao on 2022/6/29.
//
#include "dpi_hs_search.h"

//初始化hyperscan scratch space
//dpi_hs_search::dpi_hs_search(dpi_detector_t *dt)
//                :detector(dt){
//    DEBUG_LOG_FUNC_ENTRY(DBG_INIT|DBG_DETECT,NULL);
//    HyperscanActivate();
//}
//
//void dpi_hs_search::ActivateScratch(hs_scratch_t **build_scratch,
//                                        hs_scratch_t **scan_scratch)  {
//    hs_free_scratch(*scan_scratch);
//    *scan_scratch = *build_scratch;
//    *build_scratch = NULL;
//}
//
//void dpi_hs_search::HyperscanActivate() {
//    ActivateScratch(&detector->dlp_hs_mpse_build_scratch, &detector->dlp_hs_mpse_scan_scratch);
//    ActivateScratch(&detector->dlp_hs_pcre_build_scratch, &detector->dlp_hs_pcre_scan_scratch);
//}
//
//void dpi_hs_search::HyperscanActivateMpse() {
//    ActivateScratch(&detector->dlp_hs_mpse_build_scratch, &detector->dlp_hs_mpse_scan_scratch);
//}
//
//void dpi_hs_search::HyperscanActivatePcre() {
//    ActivateScratch(&detector->dlp_hs_pcre_build_scratch, &detector->dlp_hs_pcre_scan_scratch);
//}
//
//dpi_hyperscan_pm_t * dpi_hs_search::dpi_hs_create(){
//    dpi_hyperscan_pm_t *pm = (dpi_hyperscan_pm_t *) calloc(1, sizeof(dpi_hyperscan_pm_t));
//
//    if (!pm) {
//        DEBUG_LOG(DBG_DETECT, NULL, "Unable to allocate memory for hyperscan pattern match!\n");
//        return NULL;
//    }
//    pm->hs_patterns_cap = INITIAL_PATTERN_ARRAY_ALLOC_SIZE;
//    pm->hs_patterns = (dpi_hyperscan_pattern_t *)calloc(1, sizeof(dpi_hyperscan_pattern_t) * pm->hs_patterns_cap);
//    if (!pm->hs_patterns) {
//        DEBUG_LOG(DBG_DETECT, NULL, "Unable to allocate memory for hyperscan pattern match sigature!\n");
//        free(pm);
//        return NULL;
//    }
//
//    return pm;
//}
//
//void * dpi_hs_search::dpi_dlp_hs_search_create() {
//    dpi_hs_search_t *hs_search = (dpi_hs_search_t *)calloc(1, sizeof(dpi_hs_search_t));
//
//    if (hs_search != NULL) {
//        dpi_sig_context_class_t c;
//        for (c = DPI_SIG_CONTEXT_CLASS_NC; c < DPI_SIG_CONTEXT_CLASS_MAX; c = dpi_sig_context_class_t(c + 1)) {
//            hs_search->data[c].hs_pm = dpi_hs_create();
//            CDS_INIT_LIST_HEAD(&hs_search->data[c].nc_sigs);
//        }
//    }
//
//    return hs_search;
//}
//
//dpi_hs_search::~dpi_hs_search() {
//
//}

dpi_hs_search::dpi_hs_search() {

}
