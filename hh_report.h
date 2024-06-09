#pragma once

#include <time.h>

#include <windows.h>
#include <pe_sieve_api.h>
#include <map>
#include <vector>

#include "hh_params.h"

class HHScanReport
{
public:
    HHScanReport(DWORD start_tick, time_t start_time)
        : startTick(start_tick), endTick(0),
        startTime(start_time), endTime(0)
    {
    }

    bool setEndTick(DWORD end_tick, time_t end_time)
    {
        if (end_tick < this->startTick) {
            return false;
        }
        this->endTick = end_tick;
        this->endTime = end_time;
        return true;
    }

    DWORD getScanTime() const
    {
        if (startTick == 0 || endTick == 0) return 0;
        return (this->endTick - this->startTick);
    }

    bool appendReport(pesieve::t_report &scan_report, const std::wstring &img_name);

    size_t countSuspicious() const
    {
        return suspicious.size();
    }

    size_t countTotal() const
    {
        return pidToReport.size();
    }

    std::string toString(bool suspiciousOnly = true);

protected:
    size_t reportsToString(std::wstringstream &stream, bool suspiciousOnly = true);

    std::string toJSON(const t_hh_params &params);
    size_t reportsToJSON(std::wstringstream &stream, size_t level, const t_hh_params &params);

    time_t startTime;
    time_t endTime;

    DWORD startTick;
    DWORD endTick;

    std::map<DWORD, pesieve::t_report> pidToReport;
    std::map<DWORD, std::wstring> pidToName;
    std::vector<DWORD> suspicious;

    friend class HHScanner;
};
