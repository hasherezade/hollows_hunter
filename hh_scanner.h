#pragma once

#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

#include <vector>

#include "hh_params.h"
#include "hh_report.h"

#define PARAM_LIST_SEPARATOR ';'

class HHScanner {
public:
    HHScanner(t_hh_params &_args)
        : hh_args(_args)
    {
    }

    HHScanReport* scan();
    void summarizeScan(HHScanReport *hh_report);

protected:
    void initOutDir(time_t start_time);

    t_hh_params &hh_args;
    std::string outDir;
};

