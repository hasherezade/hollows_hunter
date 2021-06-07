#include "hh_scanner.h"

#include <iostream>

#include <fstream>
#include <sstream>
#include <time.h>

#include "util/suspend.h"
#include "util/util.h"
#include "util/time_util.h"
#include "term_util.h"

using namespace pesieve;

bool is_wow_64(HANDLE process)
{
    FARPROC procPtr = GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    if (!procPtr) {
        //this system does not have a function IsWow64Process
        return false;
    }
    BOOL(WINAPI * is_process_wow64)(IN HANDLE, OUT PBOOL)
        = (BOOL(WINAPI*)(IN HANDLE, OUT PBOOL))procPtr;

    BOOL isCurrWow64 = FALSE;
    if (!is_process_wow64(process, &isCurrWow64)) {
        return false;
    }
    return isCurrWow64 ? true : false;
}

std::string join_path(const std::string &baseDir, const std::string &subpath)
{
    std::stringstream stream;
    if (baseDir.length() > 0) {
        stream << baseDir;
        stream << "\\";
    }
    stream << subpath;
    return stream.str();
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

bool set_output_dir(t_params &args, const std::string &new_dir)
{
    const size_t new_len = new_dir.length();
    if (!new_len) return false;

    const char* new_dir_cstr = new_dir.c_str();
    size_t buffer_len = sizeof(args.output_dir) - 1; //leave one char for '\0'
    if (new_len > buffer_len) return false;

    memset(args.output_dir, 0, buffer_len);
    memcpy(args.output_dir, new_dir_cstr, new_len);
    return true;
}

bool get_process_info(DWORD processID, CHAR szProcessName[MAX_PATH], bool &isWow64)
{
    memset(szProcessName, 0, MAX_PATH);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) {
        return false;
    }

    HMODULE hMod = nullptr;
    DWORD cbNeeded = 0;
    bool is_ok = false;
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseNameA(hProcess, hMod, szProcessName, MAX_PATH);
        is_ok = true;
    }
    isWow64 = is_wow_64(hProcess);
    CloseHandle(hProcess);
    return is_ok;
}

size_t suspend_suspicious(std::vector<DWORD> &suspicious_pids)
{
    size_t done = 0;
    std::vector<DWORD>::iterator itr;
    for (itr = suspicious_pids.begin(); itr != suspicious_pids.end(); ++itr) {
        DWORD pid = *itr;
        if (!suspend_process(pid)) {
            std::cerr << "Could not suspend the process. PID = " << pid << std::endl;
        }
    }
    return done;
}

size_t kill_suspicious(std::vector<DWORD> &suspicious_pids)
{
    size_t killed = 0;
    std::vector<DWORD>::iterator itr;
    for (itr = suspicious_pids.begin(); itr != suspicious_pids.end(); ++itr) {
        DWORD pid = *itr;
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) {
            continue;
        }
        if (TerminateProcess(hProcess, 0)) {
            killed++;
        }
        else {
            std::cerr << "Could not terminate the process. PID = " << pid << std::endl;
        }
        CloseHandle(hProcess);
    }
    return killed;
}

bool is_searched_name(const char* processName, std::set<std::string> &names_list)
{
    std::set<std::string>::iterator itr;
    for (itr = names_list.begin(); itr != names_list.end(); ++itr) {
        const char* searchedName = itr->c_str();
        if (_stricmp(processName, searchedName) == 0) {
            return true;
        }
    }
    return false;
}

bool is_searched_pid(long pid, std::set<std::string> &pids_list)
{
    std::set<std::string>::iterator itr;
    for (itr = pids_list.begin(); itr != pids_list.end(); ++itr) {
        const char* sPid = itr->c_str();
        long number = get_number(sPid);
        if (pid == number) {
            return true;
        }
    }
    return false;
}

//----

HHScanner::HHScanner(t_hh_params &_args)
    : hh_args(_args)
{
    initTime = time(NULL);
    isScannerWow64 = is_wow_64(GetCurrentProcess());
}

bool HHScanner::isScannerCompatibile()
{
#ifndef _WIN64
    if (is_wow_64(GetCurrentProcess())) {
        return false;
    }
#endif
    return true;
}

void HHScanner::initOutDir(time_t scan_time, pesieve::t_params &pesieve_args)
{
    //set unique path
    if (hh_args.unique_dir) {
        this->outDir = make_dir_name(hh_args.out_dir, scan_time);
        set_output_dir(pesieve_args, outDir);
    }
    else {
        this->outDir = hh_args.out_dir;
        set_output_dir(pesieve_args, hh_args.out_dir);
    }
}

std::string list_to_str(std::set<std::string> &list)
{
    std::stringstream stream;

    std::set<std::string>::iterator itr;
    for (itr = list.begin(); itr != list.end(); ) {
        const std::string &next_str = *itr;
        stream << next_str;
        ++itr;
        if (itr != list.end()) {
            stream << ", ";
        }
    }
    return stream.str();
}

HHScanReport* HHScanner::scan()
{
    const size_t max_processes = 1024;
    DWORD aProcesses[max_processes], cbNeeded;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return NULL;
    }
    //calculate how many process identifiers were returned.
    size_t cProcesses = cbNeeded / sizeof(DWORD);
    if (cProcesses == 0) {
        return NULL;
    }

    std::set<std::string> names_list;
    std::set<std::string> pids_list;
    std::set<std::string> ignored_names_list;

    std::string delim(1, PARAM_LIST_SEPARATOR);
    strip_to_list(hh_args.pname, delim, names_list);
    strip_to_list(hh_args.pids, delim, pids_list);
    strip_to_list(hh_args.pnames_ignored, delim, ignored_names_list);

    const bool check_time = (hh_args.ptimes != TIME_UNDEFINED) ? true : false;
#ifdef _DEBUG
    if (check_time) {
        std::cout << "Init Time: " << std::hex << this->initTime << std::endl;
    }
#endif
    const time_t scan_start = time(NULL); //start time of the current scan
    pesieve::t_params &pesieve_args = this->hh_args.pesieve_args;
    initOutDir(scan_start, pesieve_args);

    HHScanReport *my_report = new HHScanReport(GetTickCount(), scan_start);

    bool found = false;
    size_t ignored_count = 0;
    for (size_t i = 0; i < cProcesses; i++) {
        if (aProcesses[i] == 0) continue;

        DWORD pid = aProcesses[i];
        char image_buf[MAX_PATH] = { 0 };
        bool is_process_wow64 = false;
        get_process_info(pid, image_buf, is_process_wow64);

        // filter by the time
        time_t time_diff = 0;
        if (check_time) { // if the parameter was set
            const time_t process_time = util::process_start_time(pid);
            if (process_time == INVALID_TIME) continue; //skip process if cannot retrieve the time

            // if HH was started after the process
            if (this->initTime > process_time) {
                time_diff = this->initTime - process_time;
                if (time_diff > hh_args.ptimes) continue; // skip process created before the supplied time
            }
        }
        //filter by the names/PIDs
        if (names_list.size() || pids_list.size()) {
            if (!is_searched_name(image_buf, names_list) && !is_searched_pid(pid, pids_list)) {
                //it is not the searched process, so skip it
                continue;
            }
            found = true;
        }
        if (!found && ignored_names_list.size()) {
            if (is_searched_name(image_buf, ignored_names_list)) {
                //it is ignored name
                ignored_count++;
                continue;
            }
        }
        if (!hh_args.quiet) {
            std::cout << ">> Scanning PID: " << std::dec << pid;
            if (strlen(image_buf)) {
                std::cout << " : " << image_buf;
            }
            if (is_process_wow64) {
                std::cout << " : 32b" ;
            }
            if (check_time) {
                std::cout << " : " << time_diff << "s";
            }
            std::cout << std::endl;
        }
        pesieve_args.pid = pid;
        pesieve::t_report report = PESieve_scan(pesieve_args);
        my_report->appendReport(report, image_buf);
        
        if (!hh_args.quiet) {
            if (report.errors == pesieve::ERROR_SCAN_FAILURE) {
                WORD old_color = set_color(MAKE_COLOR(SILVER, DARK_RED));
                if (report.errors == pesieve::ERROR_SCAN_FAILURE) {
                    std::cout << "[!] Could not access: " << std::dec << pid;
#ifndef _WIN64
                    if (this->isScannerWow64 != is_process_wow64) {
                        std::cout << " : 64b";
                    }
#endif
                }
                set_color(old_color);
                std::cout << std::endl;
                continue;
            }
#ifndef _WIN64
            if (report.is_64bit) {
                WORD old_color = set_color(MAKE_COLOR(SILVER, DARK_MAGENTA));
                std::cout << "[!] Partial scan: " << std::dec << pid << " : " << (report.is_64bit ? 64 : 32) << "b";
                set_color(old_color);
                std::cout << std::endl;
            }
#endif
            if (report.suspicious) {
                int color = YELLOW;
                if (report.replaced || report.implanted) {
                    color = RED;
                }
                if (report.is_managed) {
                    color = MAKE_COLOR(color, DARK_BLUE);
                }
                WORD old_color = set_color(color);
                std::cout << ">> Detected: " << std::dec << pid;
                if (report.is_managed) {
                    std::cout << " [.NET]";
                }
                set_color(old_color);
                std::cout << std::endl;
            }
        }
    }

    if (!found && hh_args.pname.length() > 0) {
        if (!hh_args.quiet) {
            std::cout << "[WARNING] No process from the list: {" << list_to_str(names_list) << "} was found!" << std::endl;
        }
    }
    if (ignored_count > 0) {
        if (!hh_args.quiet) {
            std::string info1 = (ignored_count > 1) ? "processes" : "process";
            std::string info2 = (ignored_count > 1) ? "were" : "was";
            std::cout << "[INFO] " << std::dec << ignored_count << " "<< info1 << " from the list : {" << list_to_str(ignored_names_list) << "} "<< info2 << " ignored!" << std::endl;
        }
    }
    my_report->setEndTick(GetTickCount(), time(NULL));
    return my_report;
}

bool write_to_file(const std::string &report_path, const std::string &summary_str, const bool append)
{
    std::ofstream final_report;
    if (append) {
        final_report.open(report_path, std::ios_base::app);
    }
    else {
        final_report.open(report_path);
    }
    if (final_report.is_open()) {
        final_report << summary_str;
        final_report.close();
        return true;
    }
    return false;
}


void HHScanner::summarizeScan(HHScanReport *hh_report)
{
    if (!hh_report) return;
    std::string summary_str;

    if (!this->hh_args.json_output) {
        summary_str = hh_report->toString();
        std::cout << summary_str;
    }
    else {
        summary_str = hh_report->toJSON(this->hh_args);
        std::cout << summary_str;
    }

    if (hh_args.pesieve_args.out_filter != OUT_NO_DIR) {
        //file the same report into the directory with dumps:
        if (hh_report->suspicious.size()) {
            std::string report_path = join_path(this->outDir, "summary.json");
            write_to_file(report_path, hh_report->toJSON(this->hh_args), false);
        }
    }
    if (hh_args.log) {
        write_to_file("hollows_hunter.log", summary_str, true);
    }
    if (hh_args.suspend_suspicious) {
        suspend_suspicious(hh_report->suspicious);
    }
    if (hh_args.kill_suspicious) {
        kill_suspicious(hh_report->suspicious);
    }
}
