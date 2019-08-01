#pragma once
#include <Windows.h>

bool suspend_process(DWORD processId);

bool resume_process(DWORD processId);

bool is_process_associated(DWORD processId);

DWORD GetParentProcessID(DWORD dwPID);
