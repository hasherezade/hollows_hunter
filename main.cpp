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

#define VERSION "0.3.0.1"

using namespace hhunter::util;

#define HH_INFO 0

void compatibility_alert()
{
    print_in_color(WARNING_COLOR, "[!] Scanner mismatch! For a 64-bit OS, use the 64-bit version of the scanner!\n");
}

std::string version_to_str(DWORD version)
{
    BYTE *chunks = (BYTE*) &version;
    std::stringstream stream;
    stream << std::hex <<
        (int)chunks[3] << "." <<
        (int)chunks[2] << "." <<
        (int)chunks[1] << "." <<
        (int)chunks[0];

    return stream.str();
}

std::string is_enabled(bool param)
{
    if (param) {
        return "Enabled";
    }
    return "Disabled";
}

void print_version(WORD info_color = HILIGHTED_COLOR)
{
    WORD old_color = set_color(info_color);
    std::cout << "HollowsHunter v." << VERSION;
    DWORD pesieve_ver = PESieve_version;
#ifdef _WIN64
    std::cout << " (x64)" << "\n";
#else
    std::cout << " (x86)" << "\n";
#endif
    std::cout << "Built on: " << __DATE__ << "\n\n";
    std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver);
    set_color(old_color);
    std::cout << std::endl;
}

void deploy_scan(t_hh_params &hh_args)
{
    if (hh_args.pesieve_args.data >= pesieve::PE_DATA_SCAN_INACCESSIBLE && hh_args.pesieve_args.make_reflection == false) {
        print_in_color(RED, "[WARNING] Scanning of inaccessible pages is enabled only in the reflection mode!\n");
    }
    hhunter::util::set_debug_privilege();
    HHScanner hhunter(hh_args);
    do {
        HHScanReport *report = hhunter.scan();
        if (report) {
            hhunter.summarizeScan(report);
            delete report;
        }
        if (!HHScanner::isScannerCompatibile()) {
            compatibility_alert();
        }
    } while (hh_args.loop_scanning);
}

int main(int argc, char *argv[])
{
    t_hh_params hh_args;
    hh_args_init(hh_args);

    bool info_req = false;
    HHParams uParams(VERSION);
    if (argc < 2) {
        uParams.printBanner();
        uParams.info(false, "", false);
        system("pause");
        return PESIEVE_INFO;
    }
    if (!uParams.parse(argc, argv)) {
        return PESIEVE_INFO;
    }
    uParams.fillStruct(hh_args);

    print_version();
    std::cout << std::endl;
    deploy_scan(hh_args);
    return 0;
}
