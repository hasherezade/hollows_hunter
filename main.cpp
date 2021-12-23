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

#define VERSION "0.3.1.5"

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

int main(int argc, char *argv[])
{
    t_hh_params hh_args;
    hh_args_init(hh_args);

    bool info_req = false;
    HHParams uParams(VERSION);

    if (!uParams.parse(argc, argv)) {
        return PESIEVE_INFO;
    }
    uParams.fillStruct(hh_args);
    print_version(VERSION);
    std::cout << std::endl;
    if (argc < 2) {
        print_in_color(WHITE, "Default scan deployed.");
        std::cout << std::endl;
    }
    return deploy_scan(hh_args);
}
