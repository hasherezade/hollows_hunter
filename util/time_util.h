#pragma once

#include <windows.h>
#include <time.h>
#include <iostream>

#define INVALID_TIME LONGLONG(-1)

namespace util {
    std::wstring strtime(const time_t t);

    LONGLONG LargeTime_to_POSIX(LARGE_INTEGER date);

    LONGLONG FileTime_to_POSIX(FILETIME ft);

    LONGLONG process_start_time(DWORD processID);
};
