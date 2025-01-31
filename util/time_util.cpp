#include "time_util.h"
#include <codecvt>
#include <locale>
#include <string>
#include <sstream>

#include <iostream>
#include <iomanip>
#include <ctime>
#include <cmath>

#include "ntddk.h"
#include "custom_buffer.h"

std::wstring util::strtime(const time_t t)
{
    struct tm time_info;
    if (localtime_s(&time_info, &t) == 0) {
        std::wstringstream str;
        str << std::put_time(&time_info, L"%c");
        std::wstring result = str.str();
        return result;
    }
    return L"";
}

// snippet from: https://www.frenk.com/2009/12/convert-filetime-to-unix-timestamp/
LONGLONG util::LargeTime_to_POSIX(LARGE_INTEGER date)
{
    // takes the last modified date
    LARGE_INTEGER adjust;

    // 100-nanoseconds = milliseconds * 10000
    adjust.QuadPart = 11644473600000 * 10000;

    // removes the diff between 1970 and 1601
    date.QuadPart -= adjust.QuadPart;

    // converts back from 100-nanoseconds to seconds
    return date.QuadPart / 10000000;
}


LONGLONG util::FileTime_to_POSIX(FILETIME ft)
{
    // takes the last modified date
    LARGE_INTEGER date;
    date.HighPart = ft.dwHighDateTime;
    date.LowPart = ft.dwLowDateTime;
    return LargeTime_to_POSIX(date);
}


//---

LONGLONG util::process_start_time(IN DWORD pid)
{
    static auto mod = GetModuleHandleA("ntdll.dll");
    if (!mod) return INVALID_TIME;

    static auto pNtQuerySystemInformation = reinterpret_cast<decltype(&NtQuerySystemInformation)>(GetProcAddress(mod, "NtQuerySystemInformation"));
    if (!pNtQuerySystemInformation)  return false;

    util::AutoBuffer bBuf;

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    while (status != STATUS_SUCCESS) {
        ULONG ret_len = 0;
        status = pNtQuerySystemInformation(SystemProcessInformation, bBuf.buf, bBuf.buf_size, &ret_len);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            if (!bBuf.alloc(ret_len)) {
                return INVALID_TIME;
            }
            continue; // try again
        }
        break; //other error, or success
    };

    if (status != STATUS_SUCCESS) {
        return INVALID_TIME;
    }

    bool found = false;
    SYSTEM_PROCESS_INFORMATION* info = (SYSTEM_PROCESS_INFORMATION*)bBuf.buf;
    while (info) {
        if (info->UniqueProcessId == pid) {
            found = true;
            break;
        }
        if (!info->NextEntryOffset) {
            break;
        }
        size_t record_size = info->NextEntryOffset;
        if (record_size < sizeof(SYSTEM_PROCESS_INFORMATION)) {
            // Record size smaller than expected, probably it is an old system that doesn not support the new version of this API
#ifdef _DEBUG
            std::cout << "The new version of SYSTEM_PROCESS_INFORMATION is not supported!\n";
#endif
            break;
        }
        info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)info + info->NextEntryOffset);
        if (!info) {
            break;
        }
    }

    if (!found) {
        return INVALID_TIME;
    }

    LARGE_INTEGER createTime = info->CreateTime;
    return util::LargeTime_to_POSIX(createTime);
}

