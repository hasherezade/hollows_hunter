#pragma once

#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

#include <vector>

#include "hh_params.h"

size_t pesieve_scan(std::vector<DWORD> &suspicious, t_hh_params &hh_args);
