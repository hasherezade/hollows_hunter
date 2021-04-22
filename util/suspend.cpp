#include "suspend.h"
#include <iostream>
#include <psapi.h>

#include "ntddk.h"

bool suspend_process(DWORD processId)
{
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    typedef LONG(NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);

    NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
        GetModuleHandleA("ntdll"), "NtSuspendProcess");
    if (!pfnNtSuspendProcess) {
        return false;
    }
    LONG res = pfnNtSuspendProcess(processHandle);
    CloseHandle(processHandle);
    if (res == S_OK) {
        return true;
    }
    return false;
}

bool resume_process(DWORD processId)
{
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    typedef LONG(NTAPI *NtResumeProcess)(IN HANDLE ProcessHandle);

    NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(
        GetModuleHandleA("ntdll"), "NtResumeProcess");
    if (!pfnNtResumeProcess) {
        return false;
    }
    LONG res = pfnNtResumeProcess(processHandle);
    CloseHandle(processHandle);
    if (res == S_OK) {
        return true;
    }
    return false;
}

bool is_process_associated(DWORD remote_pid)
{
    DWORD my_pid = GetCurrentProcessId();
    const bool is_me = remote_pid == my_pid;
    if (is_me) {
        return true;
    }

    DWORD my_parent = GetParentProcessID(my_pid);
    DWORD remote_parent = GetParentProcessID(remote_pid);

    if (my_parent == INVALID_PID || remote_parent == INVALID_PID) {
        return false;
    }

    bool is_my_child = remote_parent == my_pid;
    bool is_my_parent = my_parent == remote_pid;
    bool is_sibling = my_parent == remote_parent;

    if (!is_my_child && !is_my_parent && !is_sibling) {
        return false;
    }
    return true;
}

DWORD GetParentProcessID(DWORD dwPID)
{
    NTSTATUS ntStatus;
    DWORD dwParentPID = INVALID_PID;
    HANDLE hProcess;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ulRetLen;

    //  create entry point for 'NtQueryInformationProcess()'
    typedef NTSTATUS(__stdcall *FPTR_NtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    FPTR_NtQueryInformationProcess NtQueryInformationProcess
        = (FPTR_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        return INVALID_PID;
    }
    //  get process handle
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,
        FALSE,
        dwPID
    );
    //  could fail due to invalid PID or insufficiant privileges
    if (!hProcess)
        return INVALID_PID;

    //  gather information
    ntStatus = NtQueryInformationProcess(hProcess,
        ProcessBasicInformation,
        (void*)&pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ulRetLen
    );
    //  copy PID on success
    if (ntStatus == S_OK)
        dwParentPID = (DWORD)pbi.InheritedFromUniqueProcessId;
    CloseHandle(hProcess);
    return dwParentPID;
}
