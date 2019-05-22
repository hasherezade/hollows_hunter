#pragma once

#include <Windows.h>
#include <pe_sieve_api.h>
#include <map>
#include <vector>

class HHScanReport
{
public:
    HHScanReport(DWORD start_tick)
        : startTick(start_tick), endTick(0)
    {
    }

    bool setEndTick(DWORD end_tick)
    {
        if (end_tick < this->startTick) {
            return false;
        }
        this->endTick = end_tick;
        return true;
    }

    DWORD getScanTime() const
    {
        if (startTick == 0 || endTick == 0) return 0;
        return (this->endTick - this->startTick);
    }

    bool appendReport(t_report &scan_report, std::string img_name);

    size_t countSuspicious() const
    {
        return suspicious.size();
    }

    std::string toString();

protected:
    size_t printSuspicious(std::stringstream &stream);

    DWORD startTick;
    DWORD endTick;

    std::map<DWORD, t_report> pidToReport;
    std::map<DWORD, std::string> pidToName;
    std::vector<DWORD> suspicious;

    friend class HHScanner;
};
