#include "hollows_hunter.h"

#include <iostream>
#include <sstream>
#include <time.h>

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
        }
        else {
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

std::string make_dir_name(std::string baseDir, time_t timestamp)
{
    std::stringstream stream;
    if (baseDir.length() > 0) {
        stream << baseDir;
        stream << "\\";
    }
    stream << "scan_";
    stream << timestamp;
    return stream.str();
}

bool set_output_dir(t_params &args, const char *new_dir)
{
    if (!new_dir) return false;

    size_t new_len = strlen(new_dir);
    size_t buffer_len = sizeof(args.output_dir);
    if (new_len > buffer_len) return false;

    memset(args.output_dir, 0, buffer_len);
    memcpy(args.output_dir, new_dir, new_len);
    return true;
}

size_t deploy_scan(t_hh_params &hh_args)
{
    std::vector<DWORD> suspicious_pids;

    DWORD start_tick = GetTickCount();
    time_t start_time = time(NULL);

    //set unique path
    if (hh_args.unique_dir) {
        std::string out_dir = make_dir_name(hh_args.out_dir, start_time);
        set_output_dir(hh_args.pesieve_args, out_dir.c_str());
    }
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
