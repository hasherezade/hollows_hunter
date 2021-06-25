#include <stdio.h>

#include <string>
#include <map>
#include <vector>

#include <sstream>

#include "color_scheme.h"
#include "hh_scanner.h"
#include <pe_sieve_types.h>
#include "params_info/pe_sieve_params_print.h"
#include "params_info/param_base.h"
#include "util/process_privilege.h"
#include "util/strings_util.h"

#define VERSION "0.2.9.8"

using namespace hhunter::util;

void compatibility_alert()
{
    print_in_color(WARNING_COLOR, "[!] Scanner mismatch! For a 64-bit OS, use the 64-bit version of the scanner!\n");
}

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

void print_hooks_param(int param_color)
{
    print_param_in_color(param_color, PARAM_HOOKS);
    std::cout << "  : Detect inline hooks and in-memory patches.\n";
}

void print_uniqd_param(int param_color)
{
    print_param_in_color(param_color, PARAM_UNIQUE_DIR);
    std::cout << "\t: Make a unique, timestamped directory for the output of each scan.\n"
        << "\t(Prevents overwriting results from previous scans)\n";
}

void print_suspend_param(int param_color)
{
    print_param_in_color(param_color, PARAM_SUSPEND);
    std::cout << ": Suspend processes detected as suspicious\n";
}

void print_kill_param(int param_color)
{
    print_param_in_color(param_color, PARAM_KILL);
    std::cout << "   : Kill processes detected as suspicious\n";
}

void print_log_param(int param_color)
{
    print_param_in_color(param_color, PARAM_LOG);
    std::cout << "\t: Append each scan summary to the log.\n";
}

void print_loop_param(int param_color)
{
    print_param_in_color(param_color, PARAM_LOOP);
    std::cout << "   : Enable continuous scanning.\n";
}

void print_ptimes_param(int param_color)
{
    print_param_in_color(param_color, PARAM_PTIMES);
    std::cout << " <N seconds>\n\t: Scan only processes created N seconds before HH, or later.\n";
}

void print_pignore_param(int param_color)
{
    print_param_in_color(param_color, PARAM_PROCESSES_IGNORE);
    std::cout << " <process_name>\n\t: Do not scan process/es with given name/s (separated by '" << PARAM_LIST_SEPARATOR << "').\n"
        "\t  Example: explorer.exe" << PARAM_LIST_SEPARATOR << "conhost.exe\n";
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
    WORD logo_color = DARK_MAGENTA;

    WORD curr_color = 0;
    if (get_current_color(STD_OUTPUT_HANDLE, curr_color)) {
        WORD current_bg = GET_BG_COLOR(curr_color);
        if (current_bg == logo_color) {
            logo_color = MAKE_COLOR(CYAN, current_bg);
        }
    }
    WORD old_color = set_color(logo_color);
    std::cout << "\n" << logo << std::endl;
    set_color(old_color);
}

size_t print_params_block(std::string block_name, std::map<std::string, void(*)(int)> params_block, const std::string &filter)
{
    const int hdr_color = HEADER_COLOR;
    const int param_color = HILIGHTED_COLOR;
    const int separator_color = SEPARATOR_COLOR;

    const bool has_filter = filter.length() > 0 ? true : false;
    bool has_any = false;

    std::map<std::string, void(*)(int)>::iterator itr;
    for (itr = params_block.begin(); itr != params_block.end();itr++) {
        const std::string &param = itr->first;
        if (has_filter) {
            stringsim_type sim_type = is_string_similar(param, filter);
            if (sim_type != SIM_NONE) has_any = true;
        }
        else {
            has_any = true;
        }
    }
    if (!has_any) return 0;

    int p_color = param_color;
    if (block_name.length()) {
        print_in_color(separator_color, "\n---" + block_name + "---\n");
    }
    size_t counter = 0;
    for (itr = params_block.begin(); itr != params_block.end();itr++) {
        const std::string &param = itr->first;
        if (filter.length() > 0) {
            const stringsim_type sim_type = is_string_similar(param, filter);
            p_color = (sim_type != SIM_NONE) ? ERROR_COLOR : param_color;
            if (sim_type == SIM_NONE) continue;
        }
        void(*info)(int) = itr->second;
        if (!info) continue;
        info(p_color);
        counter++;
    }
    if (has_filter) {
        print_in_color(INACTIVE_COLOR, "\n[...]\n");
    }
    return counter;
}

void print_help(std::string filter="")
{
    const int hdr_color = HEADER_COLOR;
    const int param_color = HILIGHTED_COLOR;
    const int separator_color = SEPARATOR_COLOR;

    print_in_color(hdr_color, "Optional: \n");
    size_t cntr = 0;

    std::map<std::string, void(*)(int)> scan_params;
    std::map<std::string, void(*)(int)> scan_target_params;
    std::map<std::string, void(*)(int)> scanner_params;
    std::map<std::string, void(*)(int)> scan_exclusions;

    scan_target_params[PARAM_PID] = print_pid_param;
    scan_target_params[PARAM_PNAME] = print_pname_param;
    scan_params[PARAM_HOOKS] = print_hooks_param;

    scan_params[PARAM_IAT] = print_iat_param;
    scan_params[PARAM_SHELLCODE] = print_shellc_param;
    scan_params[PARAM_DATA] = print_data_param;

    scan_exclusions[PARAM_MODULES_IGNORE] = print_mignore_param;
    scan_exclusions[PARAM_PROCESSES_IGNORE] = print_pignore_param;
    scan_exclusions[PARAM_DOTNET_POLICY] = print_dnet_param;
    scan_target_params[PARAM_PTIMES] = print_ptimes_param;

    scanner_params[PARAM_LOOP] = print_loop_param;
    scanner_params[PARAM_REFLECTION] = print_refl_param;
    scanner_params[PARAM_QUIET] = print_quiet_param;

    cntr += print_params_block("scan targets", scan_target_params, filter);
    cntr += print_params_block("scanner settings", scanner_params, filter);
    cntr += print_params_block("scan exclusions", scan_exclusions, filter);
    cntr += print_params_block("scan options", scan_params, filter);

    std::map<std::string, void(*)(int)> dump_params;
    dump_params[PARAM_IMP_REC] = print_imprec_param;
    dump_params[PARAM_DUMP_MODE] = print_dmode_param;
    dump_params[PARAM_MINIDUMP] = print_minidump_param;
    cntr += print_params_block("dump options", dump_params, filter);

    std::map<std::string, void(*)(int)> post_scan_params;
    post_scan_params[PARAM_SUSPEND] = print_suspend_param;
    post_scan_params[PARAM_KILL] = print_kill_param;
    cntr += print_params_block("post-scan actions", post_scan_params, filter);

    std::map<std::string, void(*)(int)> out_params;
    out_params[PARAM_OUT_FILTER] = print_out_filter_param;
    out_params[PARAM_DIR] = print_output_dir_param;
    out_params[PARAM_UNIQUE_DIR] = print_uniqd_param;
    out_params[PARAM_LOG] = print_log_param;
    out_params[PARAM_JSON] = print_json_param;
    out_params[PARAM_JSON_LVL] = print_json_level_param;
    cntr += print_params_block("output options", out_params, filter);
    if (cntr == 0) {
        print_in_color(INACTIVE_COLOR, "\n[...]\n");
    }
    print_in_color(hdr_color, "\nInfo: \n\n");

    print_param_in_color(param_color, PARAM_HELP);
    std::cout << "    : Print this help.\n";
    print_param_in_color(param_color, PARAM_VERSION);
    std::cout << " : Print version number.\n";
    print_param_in_color(param_color, PARAM_DEFAULTS);
    std::cout << " : Print information about the default settings.\n";
    std::cout << "---" << std::endl;
    if (!HHScanner::isScannerCompatibile()) {
        compatibility_alert();
    }
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
    std::cout << PARAM_DATA << " : " << hh_args.pesieve_args.data << "\n";
    if (hh_args.pesieve_args.data == pesieve::PE_DATA_NO_SCAN) {
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

    //Parse parameters
    for (int i = 1; i < argc; i++) {
        if (!info_req && !is_param(argv[i])) {
            print_logo();
            print_version();
            std::cout << "\n";
            print_unknown_param(argv[i]);
            print_in_color(HILIGHTED_COLOR, "Similar parameters:\n\n");
            print_help(argv[i]);
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
        else if (get_cstr_param(argc, argv, param, i,
            PARAM_MODULES_IGNORE,
            hh_args.pesieve_args.modules_ignored,
            MAX_MODULE_BUF_LEN,
            info_req,
            print_mignore_param))
        {
            continue;
        }
        else if (get_string_param(argc, argv, param, i,
            PARAM_PROCESSES_IGNORE,
            hh_args.pnames_ignored,
            info_req,
            print_pignore_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_HOOKS,
            hh_args.pesieve_args.no_hooks,
            true,
            info_req,
            print_hooks_param))
        {
            //the HH argument is "hooks" and the PE-sieve param is "no_hooks", so we need to negate what we've got
            hh_args.pesieve_args.no_hooks = !hh_args.pesieve_args.no_hooks;
            continue;
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
            pesieve::PE_DNET_SKIP_MAPPING,
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
        else if (get_int_param(argc, argv, param, i,
            PARAM_PTIMES,
            hh_args.ptimes,
            0LL,
            info_req,
            print_ptimes_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_LOG,
            hh_args.log,
            true,
            info_req,
            print_log_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_JSON,
            hh_args.json_output,
            true,
            info_req,
            print_json_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_LOOP,
            hh_args.loop_scanning,
            true,
            info_req,
            print_loop_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_SUSPEND,
            hh_args.suspend_suspicious,
            true,
            info_req,
            print_suspend_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_KILL,
            hh_args.kill_suspicious,
            true,
            info_req,
            print_kill_param))
        {
            continue;
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
        else if (get_int_param(argc, argv, param, i,
            PARAM_QUIET,
            hh_args.quiet,
            true,
            info_req,
            print_quiet_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_UNIQUE_DIR,
            hh_args.unique_dir,
            true,
            info_req,
            print_uniqd_param))
        {
            continue;
        }
        else if (get_string_param(argc, argv, param, i,
            PARAM_DIR,
            hh_args.out_dir,
            info_req,
            print_output_dir_param))
        {
            continue;
        }
        //get_string_param
        else if (get_int_param(argc, argv, param, i,
            PARAM_MINIDUMP,
            hh_args.pesieve_args.minidump,
            true,
            info_req,
            print_minidump_param))
        {
            continue;
        }
        else if (get_int_param(argc, argv, param, i,
            PARAM_JSON_LVL,
            hh_args.pesieve_args.json_lvl,
            pesieve::JSON_BASIC,
            info_req,
            print_json_level_param))
        {
            hh_args.pesieve_args.json_lvl = normalize_json_level(hh_args.pesieve_args.json_lvl);
            continue;
        }
        else if (!info_req && strlen(argv[i]) > 0) {
            print_unknown_param(argv[i]);
            print_in_color(HILIGHTED_COLOR, "Similar parameters:\n\n");
            print_help(param);
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
