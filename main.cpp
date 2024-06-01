#define WIN32_LEAN_AND_MEAN

#ifndef _WIN64
#undef USE_ETW //ETW support works only for 64 bit
#endif //_WIN64

#if (_MSC_VER < 1900)
#undef USE_ETW //ETW not supported
#endif

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

// Global arguments
t_hh_params g_hh_args;

#ifdef USE_ETW
#include "etw_listener.h"
#endif

void compatibility_alert()
{
    print_in_color(WARNING_COLOR, "[!] Scanner mismatch! For a 64-bit OS, use the 64-bit version of the scanner!\n");
}

t_pesieve_res deploy_scan()
{
    t_pesieve_res scan_res = PESIEVE_NOT_DETECTED;
    hhunter::util::set_debug_privilege();
    if (g_hh_args.pesieve_args.data >= pesieve::PE_DATA_SCAN_INACCESSIBLE && g_hh_args.pesieve_args.make_reflection == false) {
        print_in_color(RED, "[WARNING] Scanning of inaccessible pages is enabled only in the reflection mode!\n");
    }
    if (g_hh_args.etw_scan)
    {
#ifdef USE_ETW
        if (!ETWstart()) {
            return PESIEVE_ERROR;
        }
#else
        std::cerr << "ETW support is disabled\n";
        return PESIEVE_ERROR;
#endif
    }
    else
    {
        HHScanner hhunter(g_hh_args);
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
        } while (g_hh_args.loop_scanning);
    }
    return scan_res;
}

int main(int argc, char *argv[])
{
    g_hh_args.init();

    bool info_req = false;
    HHParams uParams(HH_VERSION_STR);
    if (!uParams.parse(argc, argv)) {
        return PESIEVE_INFO;
    }
    uParams.fillStruct(g_hh_args);

    // if scanning of inaccessible pages was requested, auto-enable reflection mode:
    if (g_hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE || g_hh_args.pesieve_args.data == pesieve::PE_DATA_SCAN_INACCESSIBLE_ONLY) {
        if (!g_hh_args.pesieve_args.make_reflection) {
            g_hh_args.pesieve_args.make_reflection = true;
            print_in_color(RED, "[WARNING] Scanning of inaccessible pages requested: auto-enabled reflection mode!\n");
        }
    }

    print_version(HH_VERSION_STR);
    std::cout << std::endl;
    if (argc < 2) {
        print_in_color(WHITE, "Default scan deployed.");
        std::cout << std::endl;
    }
    const t_pesieve_res  res = deploy_scan();
    uParams.freeStruct(g_hh_args);
    return res;
}
