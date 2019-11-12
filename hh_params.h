#pragma once

#include <pe_sieve_api.h>
#include <string>

//HollowsHunter's parameters:
typedef struct {
    std::string pname;
    std::string out_dir;
    bool unique_dir;
    bool loop_scanning;
    bool suspend_suspicious;
    bool kill_suspicious;
    bool quiet;
    bool log;
    bool json_output;
    pesieve::t_params pesieve_args; //PE-sieve parameters
} t_hh_params;

void hh_args_init(t_hh_params &args);
