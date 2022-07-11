//
// Created by tanchao on 2022/6/29.
//

#ifndef DPI_TEST_DPI_HS_SEARCH_H
#define DPI_TEST_DPI_HS_SEARCH_H

#include "hs.h"
#include "base/debug.h"
#include "dpi_hyperscan.h"

#define INITIAL_PATTERN_ARRAY_ALLOC_SIZE 10

using namespace std;

class dpi_hs_search {
private:
    dpi_detector_t *detector;
    dpi_hs_search_t *hs_search;
    void HyperscanActivate();
    void HyperscanActivateMpse();
    void HyperscanActivatePcre();
    void ActivateScratch(hs_scratch_t **build_scratch, hs_scratch_t **scan_scratch);
    dpi_hyperscan_pm_t *dpi_hs_create();
    int dpi_dlp_hs_compile(dpi_hyperscan_pm_t *hspm, dpi_detector_t *detector);
public:
    dpi_hs_search(dpi_detector_t *dt, dpi_hs_search_t *hsSearch);
    ~dpi_hs_search();
    dpi_hs_search_t * dpi_dlp_hs_search_create();
    void dpi_dlp_hs_search_add_dlprule(dpi_sig_t *sig);
    void dpi_dlp_hs_search_compile();
    void dpi_dlp_hs_search_detect();
};

#endif //DPI_TEST_DPI_HS_SEARCH_H
