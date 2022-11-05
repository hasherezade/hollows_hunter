#include <stdio.h>

#include <string>
#include <map>
#include <vector>

#include <sstream>

#include "color_scheme.h"
#include "hh_scanner.h"

#include <pe_sieve_types.h>
#include <pe_sieve_return_codes.h>

#include "params_info/params.h"

#include "util/process_privilege.h"
#include "util/strings_util.h"
#include "hh_ver_short.h"

using namespace hhunter::util;

void compatibility_alert()
{
    print_in_color(WARNING_COLOR, "[!] Scanner mismatch! For a 64-bit OS, use the 64-bit version of the scanner!\n");
}

t_pesieve_res deploy_scan(t_hh_params &hh_args)
{
    t_pesieve_res scan_res = PESIEVE_NOT_DETECTED;
    if (hh_args.pesieve_args.data >= pesieve::PE_DATA_SCAN_INACCESSIBLE && hh_args.pesieve_args.make_reflection == false) {
        print_in_color(RED, "[WARNING] Scanning of inaccessible pages is enabled only in the reflection mode!\n");
    }
    hhunter::util::set_debug_privilege();
    HHScanner hhunter(hh_args);
    do {
        HHScanReport *report = hhunter.scan();
        if (report) {
            hhunter.summarizeScan(report);
            if (report->countSuspicious() > 0) {
                scan_res = PESIEVE_DETECTED;
            }
            delete report;
        }
        if (!HHScanner::isScannerCompatibile()) {
            compatibility_alert();
        }
    } while (hh_args.loop_scanning);

    return scan_res;
}

void free_params(t_params& args)
{
    free_strparam(args.modules_ignored);
}

int main(int argc, char *argv[])
{
    t_hh_params hh_args;
    hh_args_init(hh_args);

    bool info_req = false;
    HHParams uParams(HH_VERSION_STR);
    if (!uParams.parse(argc, argv)) {
        return PESIEVE_INFO;
    }
    uParams.fillStruct(hh_args);

    // if scanning of inaccessible pages was requested, auto-enable reflection mode:
    if (hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE || hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY) {
        if (!hh_args.pesieve_args.make_reflection) {
            hh_args.pesieve_args.make_reflection = true;
            print_in_color(RED, "[WARNING] Scanning of inaccessible pages requested: auto-enabled reflection mode!\n");
        }
    }

    print_version(HH_VERSION_STR);
    std::cout << std::endl;
    if (argc < 2) {
        print_in_color(WHITE, "Default scan deployed.");
        std::cout << std::endl;
    }
    const t_pesieve_res  res = deploy_scan(hh_args);
    free_params(hh_args.pesieve_args);
    return res;
}
