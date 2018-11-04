#include <stdio.h>

#include <string>
#include <vector>

#include <sstream>

#include "term_util.h"
#include "hollows_hunter.h"

#define VERSION "0.1.7-b"

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

//info:
#define PARAM_HELP "/help"
#define PARAM_HELP2  "/?"

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
        return "don't create the output directory at all";
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

void print_help()
{
    const int hdr_color = 14;
    const int param_color = 15;
    const int separator_color = 6;

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
    std::cout << "\t: Enable recovering imports. ";
    std::cout << "(Warning: it may slow down the scan)\n";

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

    print_in_color(param_color, PARAM_KILL);
    std::cout << "   : Kill processes detected as suspicious\n";

    print_in_color(param_color, PARAM_QUIET);
    std::cout << "\t: Print only the summary and minimalistic info.\n";
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

void print_banner()
{
    set_color(15);
    std::cout << "HollowsHunter v." << VERSION << std::endl;
    
    DWORD pesieve_ver = PESieve_version();
    std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver) << std::endl;
    std::cout << std::endl;
    unset_color();
}

size_t kill_suspicious(std::vector<DWORD> &suspicious_pids)
{
    size_t killed = 0;
    std::vector<DWORD>::iterator itr;
    for (itr = suspicious_pids.begin(); itr != suspicious_pids.end(); itr++) {
        DWORD pid = *itr;
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) {
            continue;
        }
        if (TerminateProcess(hProcess, 0)) {
            killed++;
        } else {
            std::cerr << "Could not terminate process. PID = " << pid << std::endl;
        }
        CloseHandle(hProcess);
    }
    return killed;
}

size_t print_suspicious(std::vector<DWORD> &suspicious_pids)
{
    std::vector<DWORD>::iterator itr;
    char image_buf[MAX_PATH] = { 0 };
    size_t printed = 0;
    size_t counter = 0;
    for (itr = suspicious_pids.begin(); itr != suspicious_pids.end(); itr++) {
        DWORD pid = *itr;
        std::cout << "[" << counter++ << "]:\n> PID: " << std::dec << pid << std::endl;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            continue;
        }
        memset(image_buf, 0, MAX_PATH);
        GetProcessImageFileNameA(hProcess, image_buf, MAX_PATH);
        std::cout << "> Path: " << image_buf << std::endl;
        CloseHandle(hProcess);
        printed++;
    }
    return printed;
}


size_t deploy_scan(t_hh_params &hh_args)
{
    std::vector<DWORD> suspicious_pids;

    DWORD start_tick = GetTickCount();

    pesieve_scan(suspicious_pids, hh_args);
    DWORD total_time = GetTickCount() - start_tick;
    std::cout << "--------" << std::endl;
    std::cout << "Finished scan in: " << std::dec << total_time << " milliseconds" << std::endl;

    std::cout << "SUMMARY:" << std::endl;
    std::cout << "[+] Total Suspicious: " << std::dec << suspicious_pids.size() << std::endl;
    if (suspicious_pids.size() > 0) {
        std::cout << "[+] List of suspicious: " << std::endl;
    }
    print_suspicious(suspicious_pids);
    if (hh_args.kill_suspicious) {
        kill_suspicious(suspicious_pids);
    }
    return suspicious_pids.size();
}

int main(int argc, char *argv[])
{
    print_banner();

    t_hh_params hh_args;
    hh_args_init(hh_args);

    //Parse parameters
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], PARAM_HELP) || !strcmp(argv[i], PARAM_HELP2)) {
            print_help();
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
            ++i;
        }
        else if (!strcmp(argv[i], PARAM_OUT_FILTER) && (i + 1) < argc) {
            hh_args.pesieve_args.out_filter = static_cast<t_output_filter>(atoi(argv[i + 1]));
            i++;
        }
        else if (!strcmp(argv[i], PARAM_LOOP)) {
            hh_args.loop_scanning = true;
        }
        else if (!strcmp(argv[i], PARAM_KILL)) {
            hh_args.kill_suspicious = true;
        }
        else if (!strcmp(argv[i], PARAM_PNAME) && (i + 1) < argc) {
            hh_args.pname = argv[i + 1];
        }
        else if (!strcmp(argv[i], PARAM_QUIET)) {
            hh_args.quiet = true;
        }
    }

    do {
        size_t res = deploy_scan(hh_args);
    } while (hh_args.loop_scanning);

    return 0;
}
