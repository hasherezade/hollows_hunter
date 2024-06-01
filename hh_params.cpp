#include "hh_params.h"

void hh_params::init()
{
    //reset PE-sieve params:
    memset(&pesieve_args, 0, sizeof(pesieve::t_params));

    //reset output path:
    out_dir = HH_DEFAULT_DIR;

    pesieve_args.quiet = true;
    pesieve_args.no_hooks = true;

    suspend_suspicious = false;
    kill_suspicious = false;
    loop_scanning = false;
    etw_scan = false;
    unique_dir = false;

    quiet = false;
    log = false;
    json_output = false;
    ptimes = TIME_UNDEFINED;
}

hh_params& hh_params::operator=(const hh_params& other)
{
    //copy PE-sieve params:
    ::memcpy(&pesieve_args, &other.pesieve_args, sizeof(pesieve::t_params));

    // copy HHParams
    this->out_dir = other.out_dir;

    this->suspend_suspicious = other.suspend_suspicious;
    this->kill_suspicious = other.kill_suspicious;
    this->loop_scanning = other.loop_scanning;
    this->etw_scan = other.etw_scan;
    this->unique_dir = other.unique_dir;

    this->quiet = other.quiet;
    this->log = other.log;
    this->json_output = other.json_output;
    this->ptimes = other.ptimes;

    // copy lists:
    this->names_list = other.names_list;
    this->pids_list = other.pids_list;
    this->ignored_names_list = other.ignored_names_list;

    return *this;
}