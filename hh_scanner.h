#pragma once

#include <windows.h>
#include <psapi.h>
#pragma comment(lib,"psapi.lib")

#include <vector>

#include "hh_params.h"
#include "hh_report.h"

#define PARAM_LIST_SEPARATOR ';'

class HHScanner {
public:
    // is the scanner best suited for the OS bitness
    static bool isScannerCompatibile();

    HHScanner(t_hh_params &_args);

    HHScanReport* scan();
    void summarizeScan(HHScanReport *hh_report);

protected:
    void initOutDir(time_t scan_time, pesieve::t_params &pesieve_args);

    t_hh_params &hh_args;
    std::string outDir;

    // time when HollowsHunter was initialized
    time_t initTime;
    bool isScannerWow64;
};

