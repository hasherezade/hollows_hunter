#include "pe_sieve_params_print.h"
#include "param_base.h"
#include "../term_util.h"

#include <string>
#include <psapi.h>

using namespace pesieve;

void print_dnet_param(int param_color)
{
    print_param_in_color(param_color, PARAM_DOTNET_POLICY);
    std::cout << " <*dotnet_policy>\n\t: Set the policy for scanning managed processes (.NET).\n";;
    std::cout << "*dotnet_policy:\n";
    for (size_t i = 0; i < PE_DNET_COUNT; i++) {
        t_dotnet_policy mode = (t_dotnet_policy)(i);
        std::cout << "\t" << mode << " - " << translate_dotnet_policy(mode) << "\n";
    }
}

void print_imprec_param(int param_color)
{
    print_param_in_color(param_color, PARAM_IMP_REC);
    std::cout << " <*imprec_mode>\n\t: Set in which mode the ImportTable should be recovered.\n";;
    std::cout << "*imprec_mode:\n";
    for (size_t i = 0; i < PE_IMPREC_MODES_COUNT; i++) {
        t_imprec_mode mode = (t_imprec_mode)(i);
        std::cout << "\t" << mode << " - " << translate_imprec_mode(mode) << "\n";
    }
}

void print_out_filter_param(int param_color)
{
    print_param_in_color(param_color, PARAM_OUT_FILTER);
    std::cout << " <*ofilter_id>\n\t: Filter the dumped output.\n";
    std::cout << "*ofilter_id:\n";
    for (size_t i = 0; i < OUT_FILTERS_COUNT; i++) {
        t_output_filter mode = (t_output_filter)(i);
        std::cout << "\t" << mode << " - " << translate_out_filter(mode) << "\n";
    }
}

void print_iat_param(int param_color)
{
    print_param_in_color(param_color, PARAM_IAT);
    std::cout << " <*scan_mode>\n\t: Scan for IAT hooks.\n";
    std::cout << "*scan_mode:\n";
    for (size_t i = 0; i < pesieve::PE_IATS_MODES_COUNT; i++) {
        std::cout << "\t" << i << " - " << translate_iat_scan_mode((pesieve::t_iat_scan_mode) i) << "\n";
    }
}

void print_dmode_param(int param_color)
{
    print_param_in_color(param_color, PARAM_DUMP_MODE);
    std::cout << " <*dump_mode>\n\t: Set in which mode the detected PE files should be dumped.\n";
    std::cout << "*dump_mode:\n";
    for (size_t i = 0; i < 4; i++) {
        std::cout << "\t" << i << " - " << translate_dump_mode(i) << "\n";
    }
}

void print_shellc_param(int param_color)
{
    print_param_in_color(param_color, PARAM_SHELLCODE);
    std::cout << "\t: Detect shellcode implants. (By default it detects PE only).\n";
}

void print_module_filter_param(int param_color)
{
    print_param_in_color(param_color, PARAM_MODULES_FILTER);
    std::cout << " <*mfilter_id>\n\t: Filter the scanned modules.\n";
    std::cout << "*mfilter_id:\n";
    for (DWORD i = 0; i <= LIST_MODULES_ALL; i++) {
        std::cout << "\t" << i << " - " << translate_modules_filter(i) << "\n";
    }
}

void print_mignore_param(int param_color)
{
    print_param_in_color(param_color, PARAM_MODULES_IGNORE);
    std::cout << " <module_name>\n\t: Do not scan module/s with given name/s (separated by '" << PARAM_LIST_SEPARATOR << "').\n"
        "\t  Example: kernel32.dll" << PARAM_LIST_SEPARATOR << "user32.dll\n";
}

void print_refl_param(int param_color)
{
    print_param_in_color(param_color, PARAM_REFLECTION);
    std::cout << "\t: Make a process reflection before scan.\n";
}

void print_ptimes_param(int param_color)
{
    print_param_in_color(param_color, PARAM_PTIMES);
    std::cout << " <N seconds>\n\t: Scan only processes created N seconds before HH, or later.\n";
}

void print_data_param(int param_color)
{
    print_param_in_color(param_color, PARAM_DATA);
    std::cout << " <*data_scan_mode>\n\t: Set if non-executable pages should be scanned.\n";
    std::cout << "*data_scan_mode:\n";
    for (DWORD i = 0; i < pesieve::PE_DATA_COUNT; i++) {
        std::cout << "\t" << i << " - " << translate_data_mode((pesieve::t_data_scan_mode) i) << "\n";
    }
}

void print_json_param(int param_color)
{
    print_param_in_color(param_color, PARAM_JSON);
    std::cout << "\t: Print the JSON report as the summary.\n";
}

void print_json_level_param(int param_color)
{
    print_param_in_color(param_color, PARAM_JSON_LVL);
    std::cout << " <*json_lvl>\n\t: Level of details of the JSON scan_report.\n";
    std::cout << "*json_lvl:\n";
    for (DWORD i = 0; i < pesieve::JSON_LVL_COUNT; i++) {
        std::cout << "\t" << i << " - " << translate_json_level((pesieve::t_json_level) i) << "\n";
    }
}

void print_quiet_param(int param_color)
{
    print_param_in_color(param_color, PARAM_QUIET);
    std::cout << "\t: Print only the summary. Do not log on stdout during the scan.\n";
}

void print_minidump_param(int param_color)
{
    print_param_in_color(param_color, PARAM_MINIDUMP);
    std::cout << ": Create a minidump of the full suspicious process.\n";
}

void print_output_dir_param(int param_color)
{
    print_param_in_color(param_color, PARAM_DIR);
    std::cout << " <output_dir>\n\t: Set a root directory for the output (default: current directory).\n";
}
