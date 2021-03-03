#include "time_util.h"

#include <string>
#include <sstream>

#include <iostream>
#include <iomanip>
#include <ctime>
#include <cmath>

std::string util::strtime(const time_t t)
{
    struct tm time_info;
    if (localtime_s(&time_info, &t) == 0) {
        std::stringstream str;
        str << std::put_time(&time_info, "%c");
        return str.str();
    }
    return "";
}

// snippet from: https://www.frenk.com/2009/12/convert-filetime-to-unix-timestamp/
LONGLONG util::FileTime_to_POSIX(FILETIME ft)
{
    // takes the last modified date
    LARGE_INTEGER date, adjust;
    date.HighPart = ft.dwHighDateTime;
    date.LowPart = ft.dwLowDateTime;

    // 100-nanoseconds = milliseconds * 10000
    adjust.QuadPart = 11644473600000 * 10000;

    // removes the diff between 1970 and 1601
    date.QuadPart -= adjust.QuadPart;

    // converts back from 100-nanoseconds to seconds
    return date.QuadPart / 10000000;
}

LONGLONG util::process_start_time(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
    if (!hProcess) {
        return INVALID_TIME;
    }
    FILETIME creationTime, exitTime, kernelTime, userTime;
    creationTime = exitTime = kernelTime = userTime = { 0 };
    BOOL isOk = GetProcessTimes(
        hProcess,
        &creationTime, &exitTime, &kernelTime, &userTime
    );
    CloseHandle(hProcess);
    if (!isOk) return INVALID_TIME;

    return util::FileTime_to_POSIX(creationTime);
}
