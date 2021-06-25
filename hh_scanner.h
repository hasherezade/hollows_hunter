#pragma once

#include <windows.h>
#include <psapi.h>
#pragma comment(lib,"psapi.lib")

#include <string>
#include <vector>
#include <set>

#include "hh_params.h"
#include "hh_report.h"

#define PARAM_LIST_SEPARATOR ';'

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
    void summarizeScan(HHScanReport *hh_report);

protected:
    void printScanRoundStats(size_t found, size_t ignored_count);
    size_t scanProcesses(HHScanReport &my_report);
    void printSingleReport(pesieve::t_report& report);

    t_single_scan_status scanNextProcess(DWORD pid, char* image_buf, HHScanReport &report);
    void initOutDir(time_t scan_time, pesieve::t_params &pesieve_args);
    void initScanData();

    t_hh_params &hh_args;
    std::string outDir;

    // time when HollowsHunter was initialized
    time_t initTime;
    bool isScannerWow64;

    // data
    std::set<std::string> names_list;
    std::set<std::string> pids_list;
    std::set<std::string> ignored_names_list;
};

