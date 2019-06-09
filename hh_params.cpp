#include "hh_params.h"

void hh_args_init(t_hh_params &hh_args)
{
    //reset PE-sieve params:
    memset(&hh_args.pesieve_args, 0, sizeof(pesieve::t_params));

    //reset output path:
    hh_args.out_dir = "";

    hh_args.pesieve_args.quiet = true;
    hh_args.pesieve_args.modules_filter = 3;
    hh_args.pesieve_args.no_hooks = true;

    hh_args.kill_suspicious = false;
    hh_args.loop_scanning = false;
    hh_args.pname = "";
    hh_args.unique_dir = false;

    hh_args.quiet = false;
    hh_args.log = false;
}
