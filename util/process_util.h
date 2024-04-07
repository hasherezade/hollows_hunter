#pragma once

#include <windows.h>
#include <psapi.h>

#include "suspend.h"

namespace process_util {


    inline bool is_wow_64(HANDLE process)
    {
        FARPROC procPtr = GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
        if (!procPtr) {
            //this system does not have a function IsWow64Process
            return false;
        }
        BOOL(WINAPI * is_process_wow64)(IN HANDLE, OUT PBOOL)
            = (BOOL(WINAPI*)(IN HANDLE, OUT PBOOL))procPtr;

        BOOL isCurrWow64 = FALSE;
        if (!is_process_wow64(process, &isCurrWow64)) {
            return false;
        }
        return isCurrWow64 ? true : false;
    }


    inline bool is_wow_64_by_pid(DWORD processID)
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
        if (!hProcess) {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
            if (!hProcess) return false;
        }
        return is_wow_64(hProcess);
    }


    inline bool get_process_path(DWORD processID, WCHAR* szProcessName, size_t processNameSize)
    {
        if (!szProcessName || !processNameSize) return false;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
        if (!hProcess) {
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processID);
            if (!hProcess) return false;
        }
        DWORD exeNameSize = processNameSize;
        BOOL isOK = QueryFullProcessImageNameW(hProcess, 0, szProcessName, &exeNameSize);
        CloseHandle(hProcess);

        if (!isOK || !exeNameSize) {
            return false;
        }
        return true;
    }

    inline size_t suspend_suspicious(std::vector<DWORD>& suspicious_pids)
    {
        size_t done = 0;
        std::vector<DWORD>::iterator itr;
        for (itr = suspicious_pids.begin(); itr != suspicious_pids.end(); ++itr) {
            DWORD pid = *itr;
            if (!suspend_process(pid)) {
                std::cerr << "Could not suspend the process. PID = " << pid << std::endl;
            }
        }
        return done;
    }

    inline size_t kill_suspicious(std::vector<DWORD>& suspicious_pids)
    {
        size_t killed = 0;
        std::vector<DWORD>::iterator itr;
        for (itr = suspicious_pids.begin(); itr != suspicious_pids.end(); ++itr) {
            DWORD pid = *itr;
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (!hProcess) {
                continue;
            }
            if (TerminateProcess(hProcess, 0)) {
                killed++;
            }
            else {
                std::cerr << "Could not terminate the process. PID = " << pid << std::endl;
            }
            CloseHandle(hProcess);
        }
        return killed;
    }

}; // namespace process_util

