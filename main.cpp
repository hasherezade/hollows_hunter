#include <stdio.h>

#include <string>
#include <vector>

#include <sstream>

#include "term_util.h"
#include "hollows_hunter.h"

#define VERSION "0.1"

#define PARAM_MODULES_FILTER "/mfilter"
#define PARAM_IMP_REC "/imp"
#define PARAM_HOOKS "/hooks"
#define PARAM_SHELLCODE "/shellc"
#define PARAM_PNAME "/pname"
#define PARAM_LOOP "/loop"

#define PARAM_HELP "/help"
#define PARAM_HELP2  "/?"

void print_help()
{
    const int hdr_color = 14;
    const int param_color = 15;

    print_in_color(hdr_color, "\nOptional: \n");
    print_in_color(param_color, PARAM_IMP_REC);
    std::cout << "\t: Enable recovering imports. ";
    std::cout << "(Warning: it may slow down the scan)\n";

    print_in_color(param_color, PARAM_SHELLCODE);
    std::cout << "\t: Detect shellcode implants. (By default it detects PE only).\n";

    print_in_color(param_color, PARAM_HOOKS);
    std::cout << " : Detect hooks and in-memory patches.\n";

    print_in_color(param_color, PARAM_PNAME);
    std::cout << " <process_name>\n\t: Scan only processes with given name.\n";

    print_in_color(param_color, PARAM_LOOP);
    std::cout << "  : Enable continuous scanning.\n";

#ifdef _WIN64
    print_in_color(param_color, PARAM_MODULES_FILTER);
    std::cout << " <*mfilter_id>\n\t: Filter the scanned modules.\n";
    std::cout << "*mfilter_id:\n\t0 - no filter\n\t1 - 32bit\n\t2 - 64bit\n\t3 - all (default)\n";
#endif
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

void print_banner()
{
    set_color(15);
    std::cout << "HollowsHunter v." << VERSION << std::endl;
    
    DWORD pesieve_ver = PESieve_version();
    std::cout << "using: PE-sieve v." << version_to_str(pesieve_ver) << std::endl;
    std::cout << std::endl;
    unset_color();
}

size_t deploy_scan(t_params pesieve_args, std::string pname)
{
    std::vector<DWORD> suspicious_pids;

    DWORD start_tick = GetTickCount();

    find_suspicious_process(suspicious_pids, pesieve_args, pname);
    DWORD total_time = GetTickCount() - start_tick;
    std::cout << "--------" << std::endl;
    std::cout << "Finished scan in: " << std::dec << total_time << " milliseconds" << std::endl;

    std::cout << "SUMMARY:" << std::endl;
    std::cout << "[+] Total Suspicious: " << std::dec << suspicious_pids.size() << std::endl;
    if (suspicious_pids.size() > 0) {
        std::cout << "[+] List of suspicious: " << std::endl;
    }
    char image_buf[MAX_PATH] = { 0 };
    std::vector<DWORD>::iterator itr;
    size_t i = 0;
    for (itr = suspicious_pids.begin(); itr != suspicious_pids.end(); itr++) {
        DWORD pid = *itr;
        std::cout << "[" << i++ << "]:\n> PID: " << std::dec << pid << std::endl;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess) {
            memset(image_buf, 0, MAX_PATH);
            GetProcessImageFileNameA(hProcess, image_buf, MAX_PATH);
            std::cout << "> Path: " << image_buf << std::endl;
            CloseHandle(hProcess);
        }
    }
    return suspicious_pids.size();
}

int main(int argc, char *argv[])
{
    print_banner();
    t_params args = { 0 };
    args.quiet = true;
    args.modules_filter = 3;
    args.no_hooks = true;

    bool loop_scanning = false;
    std::string pname = "";
    //Parse parameters
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], PARAM_HELP) || !strcmp(argv[i], PARAM_HELP2)) {
            print_help();
            return 0;
        }
        if (!strcmp(argv[i], PARAM_IMP_REC)) {
            args.imp_rec = true;
        }

        else if (!strcmp(argv[i], PARAM_MODULES_FILTER) && i < argc) {
            args.modules_filter = atoi(argv[i + 1]);
            if (args.modules_filter > LIST_MODULES_ALL) {
                args.modules_filter = LIST_MODULES_ALL;
            }
            i++;
        }
        else if (!strcmp(argv[i], PARAM_HOOKS)) {
            args.no_hooks = false;
        }
        else if (!strcmp(argv[i], PARAM_SHELLCODE)) {
            args.shellcode = true;
        }
        else if (!strcmp(argv[i], PARAM_LOOP)) {
            loop_scanning = true;
        }
        else if (!strcmp(argv[i], PARAM_PNAME) && i < argc) {
            pname = argv[i + 1];
        }
    }

    do {
        size_t res = deploy_scan(args, pname);
    } while (loop_scanning);

    return 0;
}
