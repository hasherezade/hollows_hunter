#pragma once

#include <pe_sieve_api.h>
#include <string>
#include <set>

#define TIME_UNDEFINED LONGLONG(-1)

//HollowsHunter's parameters:
typedef struct {
    std::string out_dir;
    bool unique_dir;
    bool loop_scanning;
    bool suspend_suspicious;
    bool kill_suspicious;
    bool quiet;
    bool log;
    bool json_output;
    LONGLONG ptimes;
    std::set<std::string> names_list;
    std::set<long> pids_list;
    std::set<std::string> ignored_names_list;
    pesieve::t_params pesieve_args; //PE-sieve parameters
} t_hh_params;

void hh_args_init(t_hh_params &args);
