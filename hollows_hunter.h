#pragma once

#include <windows.h>

#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

#include "pe_sieve_api.h"
#pragma comment(lib, "pe-sieve.lib")


size_t find_suspicious_process(std::vector<DWORD> &replaced, t_params args, std::string pname);
