#pragma once

#include <windows.h>
#include <psapi.h>
#pragma comment(lib,"psapi.lib")

#include <string>
#include <vector>
#include <set>

#include "hh_params.h"
#include "hh_report.h"


typedef enum single_status {
    SSCAN_ERROR1 = (-2),
    SSCAN_ERROR0 = (-1),
    SSCAN_NOT_MATCH = 0,
    SSCAN_IGNORED = 1,
    SSCAN_SUCCESS = 2
} t_single_scan_status;

class HHScanner {
public:
    // is the scanner best suited for the OS bitness
    static bool isScannerCompatibile();

    HHScanner(t_hh_params &_args);

    HHScanReport* scan();
    bool writeToLog(HHScanReport* hh_report);
    void summarizeScan(HHScanReport *hh_report, bool suspiciousOnly = true);

protected:
    void printScanRoundStats(size_t found, size_t ignored_count);
    size_t scanProcesses(HHScanReport &my_report);
    void printSingleReport(pesieve::t_report& report);

    t_single_scan_status scanNextProcess(DWORD pid, WCHAR* image_buf, HHScanReport &report);
    void initOutDir(time_t scan_time, pesieve::t_params &pesieve_args);

    t_hh_params &hh_args;
    std::string outDir;

    // time when HollowsHunter was initialized
    time_t initTime;
    bool isScannerWow64;
};


// Global arguments
extern t_hh_params g_hh_args;
