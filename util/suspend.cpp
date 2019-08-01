#include "suspend.h"
#include <iostream>
#include <Psapi.h>

#include "ntddk.h"

bool suspend_process(DWORD processId)
{
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    typedef LONG(NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);

    NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
        GetModuleHandleA("ntdll"), "NtSuspendProcess");

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
    bool is_me = remote_pid == my_pid;
    if (is_me) {
        return true;
    }

    DWORD my_parent = GetParentProcessID(my_pid);
    DWORD remote_parent = GetParentProcessID(remote_pid);

    bool is_my_child = remote_parent == my_pid;
    bool is_my_parent = my_parent == remote_pid;
    bool is_sibling = my_parent == remote_parent;

    if (!is_me && !is_my_child && !is_my_parent && !is_sibling) {
        return false;
    }
    return true;
}

DWORD GetParentProcessID(DWORD dwPID)
{
    NTSTATUS ntStatus;
    DWORD dwParentPID = 0xffffffff;
    HANDLE hProcess;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ulRetLen;

    //  create entry point for 'NtQueryInformationProcess()'
    typedef NTSTATUS(__stdcall *FPTR_NtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    FPTR_NtQueryInformationProcess NtQueryInformationProcess
        = (FPTR_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

    //  get process handle
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,
        FALSE,
        dwPID
    );
    //  could fail due to invalid PID or insufficiant privileges
    if (!hProcess)
        return  (0xffffffff);
    //  gather information
    ntStatus = NtQueryInformationProcess(hProcess,
        ProcessBasicInformation,
        (void*)&pbi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ulRetLen
    );
    //  copy PID on success
    if (!ntStatus)
        dwParentPID = (DWORD)pbi.InheritedFromUniqueProcessId;
    CloseHandle(hProcess);
    return  (dwParentPID);
}
