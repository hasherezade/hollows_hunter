#pragma once

#include <pe_sieve_api.h>
#include <string>
#include <set>

#define TIME_UNDEFINED LONGLONG(-1)
#define HH_DEFAULT_DIR "hollows_hunter.dumps"

//HollowsHunter's parameters:
typedef struct hh_params
{
public:
    std::string out_dir;
    bool unique_dir;
    bool loop_scanning;
    bool etw_scan;
    bool suspend_suspicious;
    bool kill_suspicious;
    bool quiet;
    bool log;
    bool json_output;
    LONGLONG ptimes;
    std::set<std::wstring> names_list;
    std::set<long> pids_list;
    std::set<std::wstring> ignored_names_list;
    pesieve::t_params pesieve_args; //PE-sieve parameters

    void init();
    hh_params& operator=(const hh_params& other);

} t_hh_params;



