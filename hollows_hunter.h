#pragma once

#include <windows.h>

#include <Psapi.h>
#pragma comment(lib,"psapi.lib")

#include "pe_sieve_api.h"
#pragma comment(lib, "pe-sieve.lib")

//HollowsHunter's parameters:
typedef struct {
    std::string pname;
    bool loop_scanning;
    bool kill_suspicious;
    t_params pesieve_args; //PE-sieve parameters
} t_hh_params;


void hh_args_init(t_hh_params &args);

size_t find_suspicious_process(std::vector<DWORD> &replaced, t_hh_params &hh_args);
