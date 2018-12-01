#pragma once

#include "pe_sieve_api.h"

//HollowsHunter's parameters:
typedef struct {
    std::string pname;
    bool loop_scanning;
    bool kill_suspicious;
    bool quiet;
    bool unique_dir;
    t_params pesieve_args; //PE-sieve parameters
} t_hh_params;

void hh_args_init(t_hh_params &args);
