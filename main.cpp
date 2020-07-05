#include <stdio.h>

#include <string>
#include <vector>

#include <sstream>

#include "color_scheme.h"
#include "hh_scanner.h"
#include <pe_sieve_types.h>
#include "params_info/pe_sieve_params_print.h"
#include "params_info/param_base.h"
#include "util/process_privilege.h"

#define VERSION "0.2.7.2"

void print_pid_param(int param_color)
{
    print_param_in_color(param_color, PARAM_PID);
    std::cout << " <target_pid>\n\t: Scan only processes with given PIDs (dec or hex, separated by '" << PARAM_LIST_SEPARATOR
        << "').\n\tExample: 5367" << PARAM_LIST_SEPARATOR << "0xa90\n";
}

void print_pname_param(int param_color)
{
    print_param_in_color(param_color, PARAM_PNAME);
    std::cout << " <process_name>\n\t: Scan only processes with given names (separated by '" << PARAM_LIST_SEPARATOR
        << "').\n\tExample: iexplore.exe" << PARAM_LIST_SEPARATOR << "firefox.exe\n";
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
    WORD old_color = set_color(5);
    std::cout << "\n" << logo << std::endl;
    set_color(old_color);
}

void print_help()
{
    const int hdr_color = HEADER_COLOR;
    const int param_color = HILIGHTED_COLOR;
    const int separator_color = SEPARATOR_COLOR;

    print_in_color(hdr_color, "Optional: \n");
    print_in_color(separator_color, "\n---scan options---\n");

    print_pid_param(param_color);
    print_pname_param(param_color);

    print_param_in_color(param_color, PARAM_HOOKS);
    std::cout << "  : Detect inline hooks and in-memory patches.\n";

    print_iat_param(param_color);

    print_shellc_param(param_color);

    print_data_param(param_color);

#ifdef _WIN64
    print_module_filter_param(param_color);
#endif

    print_mignore_param(param_color);

    print_param_in_color(param_color, PARAM_LOOP);
    std::cout << "   : Enable continuous scanning.\n";

    print_refl_param(param_color);
    print_dnet_param(param_color);

    print_in_color(separator_color, "\n---dump options---\n");

    print_imprec_param(param_color);
    print_dmode_param(param_color);

    print_in_color(separator_color, "\n---output options---\n");

    print_out_filter_param(param_color);

    print_param_in_color(param_color, PARAM_DIR);
    std::cout << " <output_dir>\n\t: Set a root directory for the output (default: current directory).\n";

    print_param_in_color(param_color, PARAM_UNIQUE_DIR);
    std::cout << "\t: Make a unique, timestamped directory for the output of each scan.\n"
        << "\t(Prevents overwriting results from previous scans)\n";

    print_param_in_color(param_color, PARAM_MINIDUMP);
    std::cout << ": Make a minidump of each detected process.\n";

    print_param_in_color(param_color, PARAM_SUSPEND);
    std::cout << ": Suspend processes detected as suspicious\n";

    print_param_in_color(param_color, PARAM_KILL);
    std::cout << "   : Kill processes detected as suspicious\n";

    print_param_in_color(param_color, PARAM_QUIET);
    std::cout << "\t: Display only the summary and minimalistic info.\n";

    print_param_in_color(param_color, PARAM_LOG);
    std::cout << "\t: Append each scan summary to the log.\n";

    print_param_in_color(param_color, PARAM_JSON);
    std::cout << "\t: Display JSON report as the summary.\n";

    print_in_color(hdr_color, "\nInfo: \n\n");

    print_param_in_color(param_color, PARAM_HELP);
    std::cout << "    : Print this help.\n";
    print_param_in_color(param_color, PARAM_VERSION);
    std::cout << " : Print version number.\n";
    print_param_in_color(param_color, PARAM_DEFAULTS);
    std::cout << " : Print information about the default settings.\n";
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

std::string is_enabled(bool param)
{
    if (param) {
        return "Enabled";
    }
    return "Disabled";
}

void print_version()
{
    WORD old_color = set_color(HILIGHTED_COLOR);
    std::cout << "HollowsHunter v." << VERSION;
#ifdef _WIN64
    std::cout << " (x64)" << "\n";
#else
    std::cout << " (x86)" << "\n";
#endif
    std::cout << "Built on: " << __DATE__ << "\n\n";

    DWORD pesieve_ver = PESieve_version;
    std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver) << "\n";
    set_color(old_color);
}

void print_defaults()
{
    std::cout << "\nBy default it detects implanted and replaced PE files.\n"
        "All detected modules are dumped.\n"
        "The reports and dumps are saved into the current directory.\n"
        "\n";

    t_hh_params hh_args;
    hh_args_init(hh_args);

    std::cout << PARAM_PNAME << " : \"" << hh_args.pname << "\"" << "\n";
    if (hh_args.pname.length() == 0 && hh_args.pids.length() == 0) {
        std::cout << "\tall running processes will be scanned\n";
    }
    else {

        std::cout << "\tonly the process with:\n";
        if (hh_args.pname.length() == 0)
            std::cout << "+ name(s): " << hh_args.pname << "\n";
        if (hh_args.pids.length() == 0)
            std::cout << "+ PID(s): " << hh_args.pids << "\n";
        std::cout << " will be scanned\n";
    }

    std::cout << PARAM_HOOKS << " : " << is_enabled(!hh_args.pesieve_args.no_hooks) << "\n";
    if (hh_args.pesieve_args.no_hooks) {
        std::cout << "\tdo not scan for hooks and patches";
    }
    else {
        std::cout << "\tinclude scan for hooks and patches";
    }
    std::cout << "\n";
    std::cout << PARAM_SHELLCODE << " : " << is_enabled(hh_args.pesieve_args.shellcode) << "\n";
    if (!hh_args.pesieve_args.shellcode) {
        std::cout << "\t do not scan for shellcodes";
    }
    std::cout << "\n";
    std::cout << PARAM_DATA << " : " << is_enabled(hh_args.pesieve_args.data) << "\n";
    if (!hh_args.pesieve_args.data) {
        std::cout << "\t scan only the memory areas that are set as executable";
    }
    std::cout << "\n";
    std::cout << PARAM_LOOP << " : " << is_enabled(hh_args.loop_scanning) << "\n";
    if (!hh_args.loop_scanning) {
        std::cout << "\tsingle scan";
    }
    std::cout << "\n";
    std::cout << PARAM_IMP_REC << " : " << std::dec << hh_args.pesieve_args.imprec_mode << "\n"
        << "\t" << translate_imprec_mode(hh_args.pesieve_args.imprec_mode) << "\n";

    std::cout << PARAM_DUMP_MODE << " : " << std::dec << hh_args.pesieve_args.dump_mode << "\n"
        << "\t" << translate_dump_mode(hh_args.pesieve_args.dump_mode) << "\n";

    std::cout << PARAM_OUT_FILTER << " : " << std::dec << hh_args.pesieve_args.out_filter << "\n"
        << "\t" << translate_out_filter(hh_args.pesieve_args.out_filter) << "\n";

    std::cout << PARAM_DIR << " : \"" << hh_args.out_dir << "\"\n";
    if (hh_args.out_dir.length() == 0) {
        std::cout << "\tcurrent directory";
    }
    std::cout << "\n";
    std::cout << PARAM_UNIQUE_DIR << " : " << is_enabled(hh_args.unique_dir) << "\n";
    if (!hh_args.unique_dir) {
        std::cout << " \tdo not create unique directory for the output";
    }
    std::cout << "\n";
    std::cout << PARAM_MINIDUMP << " : " << is_enabled(hh_args.pesieve_args.minidump) << "\n";
    if (!hh_args.pesieve_args.minidump) {
        std::cout << " \tdo not create a minidump of a detected process";
    }
    std::cout << "\n";
    std::cout << PARAM_SUSPEND << " : " << is_enabled(hh_args.suspend_suspicious) << "\n";
    if (!hh_args.suspend_suspicious) {
        std::cout << "\tdo not suspend suspicious processes";
    }
    std::cout << "\n";
    std::cout << PARAM_KILL << " : " << is_enabled(hh_args.kill_suspicious) << "\n";
    if (!hh_args.kill_suspicious) {
        std::cout << "\tdo not kill suspicious processes";
    }
    std::cout << "\n";
    std::cout << PARAM_QUIET << " : " << is_enabled(hh_args.quiet) << "\n";
    if (!hh_args.quiet) {
        std::cout << " \tprint all the information on the screen";
    }
    std::cout << "\n";
    std::cout << PARAM_LOG << " : " << is_enabled(hh_args.log) << "\n";
    if (!hh_args.log) {
        std::cout << " \tdo not add the results of the scan into the log file";
    }
    std::cout << "\n";
}

void print_unknown_param(const char *param)
{
    print_in_color(WARNING_COLOR, "Unknown parameter: ");
    std::cout << param << "\n";
}

void deploy_scan(t_hh_params &hh_args)
{
    hhunter::util::set_debug_privilege();
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
    bool info_req = false;

    //Parse parameters
    for (int i = 1; i < argc; i++) {
        if (!info_req && !is_param(argv[i])) {
            print_logo();
            print_version();
            std::cout << "\n";
            print_unknown_param(argv[i]);
            print_in_color(HILIGHTED_COLOR, "Available parameters:\n\n");
            print_help();
            return 0;
        }
        const char *param = &argv[i][1];
        if (!strcmp(param, PARAM_HELP) || !strcmp(param, PARAM_HELP2)) {
            print_logo();
            print_version();
            std::cout << "\n";
            print_help();
            return 0;
        }
        if (!strcmp(param, PARAM_VERSION) || !strcmp(param, PARAM_VERSION2)) {
            print_version();
            return 0;
        }
        if (!strcmp(param, PARAM_DEFAULTS)) {
            print_version();
            print_defaults();
            return 0;
        }
        if (get_int_param(argc, argv, param, i, 
            PARAM_IMP_REC,
            hh_args.pesieve_args.imprec_mode, 
            pesieve::PE_IMPREC_AUTO, 
            info_req, 
            print_imprec_param))
        {
            continue;
        }
        else if (get_int_param<DWORD>(argc, argv, param, i,
            PARAM_MODULES_FILTER,
            hh_args.pesieve_args.modules_filter,
            LIST_MODULES_ALL,
            info_req,
            print_module_filter_param))
        {
            continue;
        }
        else if (get_cstr_param(argc, argv, param, i,
            PARAM_MODULES_IGNORE,
            hh_args.pesieve_args.modules_ignored,
            MAX_MODULE_BUF_LEN,
            info_req,
            print_mignore_param))
        {
            continue;
        }
        else if (!strcmp(param, PARAM_HOOKS)) {
            hh_args.pesieve_args.no_hooks = false;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_DATA,
            hh_args.pesieve_args.data,
            pesieve::PE_DATA_SCAN_NO_DEP,
            info_req,
            print_data_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_SHELLCODE,
            hh_args.pesieve_args.shellcode,
            true,
            info_req,
            print_shellc_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_IAT,
            hh_args.pesieve_args.iat,
            pesieve::PE_IATS_FILTERED,
            info_req,
            print_iat_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_DOTNET_POLICY,
            hh_args.pesieve_args.dotnet_policy,
            pesieve::PE_DNET_SKIP_SHC,
            info_req,
            print_dnet_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_DUMP_MODE,
            hh_args.pesieve_args.dump_mode,
            pesieve::PE_DUMP_AUTO,
            info_req,
            print_dmode_param))
        {
            hh_args.pesieve_args.dump_mode = normalize_dump_mode(hh_args.pesieve_args.dump_mode);
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_OUT_FILTER,
            hh_args.pesieve_args.out_filter,
            pesieve::OUT_FULL,
            info_req,
            print_out_filter_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_REFLECTION,
            hh_args.pesieve_args.make_reflection,
            true,
            info_req,
            print_refl_param))
        {
            continue;
        }
        else if (!strcmp(param, PARAM_LOG)) {
            hh_args.log = true;
        }
        else if (!strcmp(param, PARAM_JSON)) {
            hh_args.json_output = true;
        }
        else if (!strcmp(param, PARAM_LOOP)) {
            hh_args.loop_scanning = true;
        }
        else if (!strcmp(param, PARAM_SUSPEND)) {
            hh_args.suspend_suspicious = true;
        }
        else if (!strcmp(param, PARAM_KILL)) {
            hh_args.kill_suspicious = true;
        }
        else if (get_string_param(argc, argv, param, i,
            PARAM_PNAME,
            hh_args.pname,
            info_req,
            print_pname_param))
        {
            continue;
        }
        else if (get_string_param(argc, argv, param, i,
            PARAM_PID,
            hh_args.pids,
            info_req,
            print_pid_param))
        {
            continue;
        }
        else if (!strcmp(param, PARAM_QUIET)) {
            hh_args.quiet = true;
        }
        else if (!strcmp(param, PARAM_UNIQUE_DIR)) {
            hh_args.unique_dir = true;
        }
        else if (!strcmp(param, PARAM_DIR) && (i + 1) < argc) {
            hh_args.out_dir = argv[i + 1];
            ++i;
        }
        else if (!strcmp(param, PARAM_MINIDUMP)) {
            hh_args.pesieve_args.minidump = true;
        }
        else if (!info_req && strlen(argv[i]) > 0) {
            print_unknown_param(argv[i]);
            print_in_color(HILIGHTED_COLOR, "Available parameters:\n\n");
            print_help();
            return 0;
        }
    }
    if (info_req) {
        return 0;
    }
    print_version();
    deploy_scan(hh_args);
    return 0;
}
