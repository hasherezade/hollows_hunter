#include <stdio.h>

#include <string>
#include <vector>

#include <sstream>

#include "term_util.h"
#include "color_scheme.h"
#include "hh_scanner.h"

#define VERSION "0.2.1"

#define PARAM_SWITCH '/'
//scan options:
#define PARAM_HOOKS "/hooks"
#define PARAM_SHELLCODE "/shellc"
#define PARAM_MODULES_FILTER "/mfilter"
#define PARAM_PNAME "/pname"
#define PARAM_LOOP "/loop"

//dump options:
#define PARAM_IMP_REC "/imp"
#define PARAM_DUMP_MODE "/dmode"

//output options:
#define PARAM_QUIET "/quiet"
#define PARAM_OUT_FILTER "/ofilter"
#define PARAM_KILL "/kill"
#define PARAM_UNIQUE_DIR "/uniqd"
#define PARAM_DIR "/dir"
#define PARAM_LOG "/log"

//info:
#define PARAM_HELP "/help"
#define PARAM_HELP2  "/?"
#define PARAM_VERSION  "/version"

std::string translate_dump_mode(const DWORD dump_mode)
{
    switch (dump_mode) {
    case 0:
        return "autodetect (default)";
    case 1:
        return "virtual (as it is in the memory, no unmapping)";
    case 2:
        return "unmapped (converted to raw using sections' raw headers)";
    case 3:
        return "realigned raw (converted raw format to be the same as virtual)";
    }
    return "undefined";
}

std::string translate_out_filter(const t_output_filter o_filter)
{
    switch (o_filter) {
    case OUT_FULL:
        return "no filter: dump everything (default)";
    case OUT_NO_DUMPS:
        return "don't dump the modified PEs, but save the report";
    case OUT_NO_DIR:
        return "don't dump any files";
    }
    return "undefined";
}

std::string translate_modules_filter(DWORD m_filter)
{
    switch (m_filter) {
    case LIST_MODULES_DEFAULT:
        return "no filter (as the scanner)";
    case LIST_MODULES_32BIT:
        return "32bit only";
    case LIST_MODULES_64BIT:
        return "64bit only";
    case LIST_MODULES_ALL:
        return "all accessible (default)";
    }
    return "undefined";
}

void print_logo()
{
    char logo2[] = ""
        "@@@  @@@  @@@@@@  @@@      @@@       @@@@@@  @@@  @@@  @@@  @@@@@@\n"
        "@@!  @@@ @@!  @@@ @@!      @@!      @@!  @@@ @@!  @@!  @@! !@@    \n"
        "@!@!@!@! @!@  !@! @!!      @!!      @!@  !@! @!!  !!@  @!@  !@@!! \n"
        "!!:  !!! !!:  !!! !!:      !!:      !!:  !!!  !:  !!:  !!      !:!\n"
        " :   : :  : :. :  : ::.: : : ::.: :  : :. :    ::.:  :::   ::.: : \n"
        "       @@@  @@@ @@@  @@@ @@@  @@@ @@@@@@@ @@@@@@@@ @@@@@@@        \n"
        "       @@!  @@@ @@!  @@@ @@!@!@@@   @!!   @@!      @@!  @@@       \n"
        "       @!@!@!@! @!@  !@! @!@@!!@!   @!!   @!!!:!   @!@!!@!        \n"
        "       !!:  !!! !!:  !!! !!:  !!!   !!:   !!:      !!: :!!        \n"
        "        :   : :  :.:: :  ::    :     :    : :: ::   :   : :       \n";
    char *logo = logo2;
    set_color(5);
    std::cout << "\n" << logo << std::endl;
}


void print_help()
{
    const int hdr_color = HEADER_COLOR;
    const int param_color = HILIGHTED_COLOR;
    const int separator_color = SEPARATOR_COLOR;

    print_in_color(hdr_color, "Optional: \n");
    print_in_color(separator_color, "\n---scan options---\n");

    print_in_color(param_color, PARAM_PNAME);
    std::cout << " <process_name>\n\t: Scan only processes with given name.\n";

    print_in_color(param_color, PARAM_HOOKS);
    std::cout << "  : Detect hooks and in-memory patches.\n";

    print_in_color(param_color, PARAM_SHELLCODE);
    std::cout << "\t: Detect shellcode implants. (By default it detects PE only).\n";

#ifdef _WIN64
    print_in_color(param_color, PARAM_MODULES_FILTER);
    std::cout << " <*mfilter_id>\n\t: Filter the scanned modules.\n";
    std::cout << "*mfilter_id:\n";
    for (size_t i = 0; i <= LIST_MODULES_ALL; i++) {
        std::cout << "\t" << i << " - " << translate_modules_filter(i) << "\n";
    }
#endif

    print_in_color(param_color, PARAM_LOOP);
    std::cout << "   : Enable continuous scanning.\n";

    print_in_color(separator_color, "\n---dump options---\n");

    print_in_color(param_color, PARAM_IMP_REC);
    std::cout << "\t: Enable recovering imports.\n";

    print_in_color(param_color, PARAM_DUMP_MODE);
    std::cout << " <*dump_mode>\n\t: Set in which mode the detected PE files should be dumped.\n";
    std::cout << "*dump_mode:\n";
    for (size_t i = 0; i < 4; i++) {
        std::cout << "\t" << i << " - " << translate_dump_mode(i) << "\n";
    }

    print_in_color(separator_color, "\n---output options---\n");

    print_in_color(param_color, PARAM_OUT_FILTER);
    std::cout << " <*ofilter_id>\n\t: Filter the dumped output.\n";
    std::cout << "*ofilter_id:\n";
    for (size_t i = 0; i < OUT_FILTERS_COUNT; i++) {
        t_output_filter mode = (t_output_filter)(i);
        std::cout << "\t" << mode << " - " << translate_out_filter(mode) << "\n";
    }

    print_in_color(param_color, PARAM_DIR);
    std::cout << " <output_dir>\n\t: Set a root directory for the output (default: current directory).\n";

    print_in_color(param_color, PARAM_UNIQUE_DIR);
    std::cout << "\t: Make a unique, timestamped directory for the output of each scan.\n"
        << "\t(Prevents overwriting results from previous scans)\n";

    print_in_color(param_color, PARAM_KILL);
    std::cout << "   : Kill processes detected as suspicious\n";

    print_in_color(param_color, PARAM_QUIET);
    std::cout << "\t: Display only the summary and minimalistic info.\n";

    print_in_color(param_color, PARAM_LOG);
    std::cout << "\t: Append each scan summary to the log.\n";

    print_in_color(hdr_color, "\nInfo: \n");
    print_in_color(param_color, PARAM_HELP);
    std::cout << "    : Print this help.\n";
    print_in_color(param_color, PARAM_VERSION);
    std::cout << " : Print version number.\n";
    std::cout << "---" << std::endl;
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

void print_version()
{
    set_color(HILIGHTED_COLOR);
    std::cout << "HollowsHunter v." << VERSION << "\n";

    DWORD pesieve_ver = PESieve_version();
    std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver) << "\n";
    unset_color();
}

void print_unknown_param(const char *param)
{
    print_in_color(WARNING_COLOR, "Unknown parameter: ");
    std::cout << param << "\n";
}

void deploy_scan(t_hh_params &hh_args)
{
    do {
        HHScanner hhunter(hh_args);
        HHScanReport *report = hhunter.scan();
        if (report) {
            hhunter.summarizeScan(report);
            delete report;
        }
    } while (hh_args.loop_scanning);
}

int main(int argc, char *argv[])
{
    t_hh_params hh_args;
    hh_args_init(hh_args);

    //Parse parameters
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], PARAM_HELP) || !strcmp(argv[i], PARAM_HELP2)) {
            print_logo();
            print_version();
            std::cout << "\n";
            print_help();
            return 0;
        }
        if (!strcmp(argv[i], PARAM_VERSION)) {
            print_version();
            return 0;
        }
        if (!strcmp(argv[i], PARAM_IMP_REC)) {
            hh_args.pesieve_args.imp_rec = true;
        }
        else if (!strcmp(argv[i], PARAM_MODULES_FILTER) && (i + 1) < argc) {
            hh_args.pesieve_args.modules_filter = atoi(argv[i + 1]);
            if (hh_args.pesieve_args.modules_filter > LIST_MODULES_ALL) {
                hh_args.pesieve_args.modules_filter = LIST_MODULES_ALL;
            }
            i++;
        }
        else if (!strcmp(argv[i], PARAM_HOOKS)) {
            hh_args.pesieve_args.no_hooks = false;
        }
        else if (!strcmp(argv[i], PARAM_SHELLCODE)) {
            hh_args.pesieve_args.shellcode = true;
        }
        else if (!strcmp(argv[i], PARAM_DUMP_MODE) && (i + 1) < argc) {
            hh_args.pesieve_args.dump_mode = atoi(argv[i + 1]);
            i++;
        }
        else if (!strcmp(argv[i], PARAM_OUT_FILTER) && (i + 1) < argc) {
            hh_args.pesieve_args.out_filter = static_cast<t_output_filter>(atoi(argv[i + 1]));
            i++;
        }
        else if (!strcmp(argv[i], PARAM_LOG)) {
            hh_args.log = true;
        }
        else if (!strcmp(argv[i], PARAM_LOOP)) {
            hh_args.loop_scanning = true;
        }
        else if (!strcmp(argv[i], PARAM_KILL)) {
            hh_args.kill_suspicious = true;
        }
        else if (!strcmp(argv[i], PARAM_PNAME) && (i + 1) < argc) {
            hh_args.pname = argv[i + 1];
            i++;
        }
        else if (!strcmp(argv[i], PARAM_QUIET)) {
            hh_args.quiet = true;
        }
        else if (!strcmp(argv[i], PARAM_UNIQUE_DIR)) {
            hh_args.unique_dir = true;
        }
        else if (!strcmp(argv[i], PARAM_DIR) && (i + 1) < argc) {
            hh_args.out_dir = argv[i + 1];
            ++i;
        }
        else if (strlen(argv[i]) > 0) {
            print_unknown_param(argv[i]);
            if (argv[i][0] == PARAM_SWITCH) {
                print_in_color(HILIGHTED_COLOR, "Available parameters:\n\n");
                print_help();
                return 0;
            }
            // if the argument didn't have a param switch, print info but do not exit
        }
    }

    print_version();
    deploy_scan(hh_args);

    return 0;
}
