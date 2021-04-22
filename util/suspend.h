#pragma once
#include <windows.h>

#define INVALID_PID (-1)

bool suspend_process(DWORD processId);

bool resume_process(DWORD processId);

// do the process with the given PID belongs to the process tree of the current process (parent/child/sibling)
bool is_process_associated(DWORD processId);

// retruns the Parent Process PID of the process with the given PID, or INVALID_PID if retrieving it was impossible
DWORD GetParentProcessID(DWORD dwPID);
