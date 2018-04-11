#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>

#define VERSION "0.1"

#define PARAM_FILTER "/mfilter"
#define PARAM_IMP_REC "/imp"
#define PARAM_HOOKS "/hooks"
#define PARAM_SHELLCODE "/shellc"

#include "pe_sieve_api.h"
#pragma comment(lib, "pe-sieve.lib")

bool is_replaced_process(t_params args)
{
    t_report report = PESieve_scan(args);
    if (report.errors) return false;
    if (report.replaced) {
        std::cout << "Found replaced: " << std::dec << args.pid << std::endl;
        return true;
    }
    if (report.suspicious) {
        std::cout << "Found suspicious: " << std::dec << args.pid << std::endl;
        return true;
    }
    return false;
}

size_t find_replaced_process(std::vector<DWORD> &replaced, t_params args)
{
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return NULL;
    }

    //calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    char image_buf[MAX_PATH] = { 0 };

    for ( i = 0; i < cProcesses; i++ ) {
        if ( aProcesses[i] == 0 ) continue;
        DWORD pid = aProcesses[i];
        std::cout << ">> Scanning PID: " << std::dec << pid << std::endl;
        args.pid = pid;
        if ( is_replaced_process(args) ) {
            replaced.push_back(pid);
        }
    }
    return replaced.size();
}

int main(int argc, char *argv[])
{
    std::cout << "HollowsHunter v." << VERSION << std::endl;

    t_params args = { 0 };
    args.quiet = true;
    args.modules_filter = 3;
    args.no_hooks = true;

    //Parse parameters
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], PARAM_IMP_REC)) {
            args.imp_rec = true;
        }
        else if (!strcmp(argv[i], PARAM_FILTER) && i < argc) {
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
    }

    std::vector<DWORD> replaced;

    DWORD start_tick = GetTickCount();

    find_replaced_process(replaced, args);
    DWORD total_time = GetTickCount() - start_tick;
    std::cout << "--------" << std::endl;
    std::cout << "Finished scan in: " << std::dec << total_time << " miliseconds" << std::endl;

    std::cout << "SUMMARY:" << std::endl;
    std::cout << "[+] Total Suspicious: " << std::dec << replaced.size() << std::endl;
    if (replaced.size() > 0) {
        std::cout << "[+] List of suspicious: " << std::endl;
    }
    char image_buf[MAX_PATH] = { 0 };
    std::vector<DWORD>::iterator itr;
    size_t i = 0;
    for (itr = replaced.begin(); itr != replaced.end(); itr++) {
        DWORD pid = *itr;
        std::cout << "[" << i++ <<"]:\n> PID: " << std::dec << pid << std::endl;
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess) {
            memset(image_buf, 0, MAX_PATH);
            GetProcessImageFileNameA(hProcess, image_buf, MAX_PATH);
            std::cout << "> Path: " << image_buf << std::endl;
            CloseHandle(hProcess);
        }
    }
    return 0;
}
