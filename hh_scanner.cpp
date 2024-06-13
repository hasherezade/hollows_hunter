#include "hh_scanner.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <codecvt>
#include <locale>
#include <time.h>
#include <tlhelp32.h>

#include "util/suspend.h"
#include "util/time_util.h"
#include "term_util.h"
#include "util/process_util.h"

#include <paramkit.h>
#include <mutex>

#define PID_FIELD_SIZE 4

using namespace pesieve;

namespace files_util {

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
}; // namespace files_util 

namespace util {

    bool is_searched_name(const WCHAR* processName, std::set<std::wstring> &names_list)
    {
        std::set<std::wstring>::iterator itr;
        for (itr = names_list.begin(); itr != names_list.end(); ++itr) {
            const WCHAR* searchedName = itr->c_str();
            if (_wcsicmp(processName, searchedName) == 0) {
                return true;
            }
        }
        return false;
    }

    bool is_searched_pid(long pid, std::set<long> &pids_list)
    {
        std::set<long>::iterator found = pids_list.find(pid);
        if (found != pids_list.end()) {
            return true;
        }
        return false;
    }

    template <typename TYPE_T>
    std::string list_to_str(std::set<TYPE_T> &list)
    {
        std::wstringstream stream;

        std::set<TYPE_T>::iterator itr;
        for (itr = list.begin(); itr != list.end(); ) {
            stream << *itr;
            ++itr;
            if (itr != list.end()) {
                stream << ", ";
            }
        }
        return std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(stream.str());
    }

}; //namespace util

//----

HHScanner::HHScanner(t_hh_params &_args)
    : hh_args(_args)
{
    initTime = time(NULL);
    isScannerWow64 = process_util::is_wow_64(GetCurrentProcess());
}

bool HHScanner::isScannerCompatibile()
{
#ifndef _WIN64
    if (process_util::is_wow_64(GetCurrentProcess())) {
        return false;
    }
#endif
    return true;
}

void HHScanner::initOutDir(time_t scan_time, pesieve::t_params &pesieve_args)
{
    //set unique path
    if (hh_args.unique_dir) {
        this->outDir = files_util::make_dir_name(hh_args.out_dir, scan_time);
        files_util::set_output_dir(pesieve_args, outDir);
    }
    else {
        this->outDir = hh_args.out_dir;
        files_util::set_output_dir(pesieve_args, hh_args.out_dir);
    }
}

void HHScanner::printScanRoundStats(size_t found, size_t ignored_count)
{
    if (!found && hh_args.names_list.size() > 0) {
        if (!hh_args.quiet) {
            const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
            std::cout << "[WARNING] No process from the list: {" << util::list_to_str(hh_args.names_list) << "} was found!" << std::endl;
        }
    }
    if (!found && hh_args.pids_list.size() > 0) {
        if (!hh_args.quiet) {
            const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
            std::cout << "[WARNING] No process from the list: {" << util::list_to_str(hh_args.pids_list) << "} was found!" << std::endl;
        }
    }
    if (ignored_count > 0) {
        if (!hh_args.quiet) {
            std::string info1 = (ignored_count > 1) ? "processes" : "process";
            std::string info2 = (ignored_count > 1) ? "were" : "was";
            const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
            std::cout << "[INFO] " << std::dec << ignored_count << " " << info1 << " from the list : {" << util::list_to_str(hh_args.ignored_names_list) << "} " << info2 << " ignored!" << std::endl;
        }
    }
}

size_t HHScanner::scanProcesses(HHScanReport &my_report)
{
    size_t count = 0;
    size_t scanned_count = 0;
    size_t ignored_count = 0;

    HANDLE hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapShot == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
        std::cerr << "[-] Could not create modules snapshot. Error: " << std::dec << err << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    //check all modules in the process, including the main module:
    if (!Process32First(hProcessSnapShot, &pe32)) {
        CloseHandle(hProcessSnapShot);
        const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
        std::cerr << "[-] Could not enumerate processes. Error: " << GetLastError() << std::endl;
        return 0;
    }
    do {
        // scan callback
        const t_single_scan_status stat = scanNextProcess(pe32.th32ProcessID, pe32.szExeFile, my_report);
        if (stat == SSCAN_IGNORED) ignored_count++;
        if (stat == SSCAN_SUCCESS) scanned_count++;
        count++;

    } while (Process32Next(hProcessSnapShot, &pe32));

    //close the handles
    CloseHandle(hProcessSnapShot);

    printScanRoundStats(scanned_count, ignored_count);
    return count;
}

void HHScanner::printSingleReport(pesieve::t_report& report)
{
    if (hh_args.quiet) return;

    if (report.errors == pesieve::ERROR_SCAN_FAILURE) {
        const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
        WORD old_color = set_color(MAKE_COLOR(SILVER, DARK_RED));
        if (report.errors == pesieve::ERROR_SCAN_FAILURE) {
            std::cout << "[!] Could not access: " << std::dec << report.pid;
        }
        set_color(old_color);
        std::cout << std::endl;
        return;
    }
#ifndef _WIN64
    if (report.is_64bit) {
        const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
        WORD old_color = set_color(MAKE_COLOR(SILVER, DARK_MAGENTA));
        std::cout << "[!] Partial scan: " << std::dec << report.pid << " : " << (report.is_64bit ? 64 : 32) << "b";
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
        const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
        WORD old_color = set_color(color);
        std::cout << ">> Detected: " << std::dec << report.pid;
        if (report.is_managed) {
            std::cout << " [.NET]";
        }
        set_color(old_color);
        std::cout << std::endl;
    }
}

t_single_scan_status HHScanner::scanNextProcess(DWORD pid, WCHAR* exe_file, HHScanReport &my_report)
{
    bool found = false;

    const bool is_process_wow64 = process_util::is_wow_64_by_pid(pid);

    const bool check_time = (hh_args.ptimes != TIME_UNDEFINED) ? true : false;
#ifdef _DEBUG
    if (check_time) {
        const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
        std::cout << "Init Time: " << std::hex << this->initTime << std::endl;
    }
#endif
    // filter by the time
    time_t time_diff = 0;
    if (check_time) { // if the parameter was set
        const time_t process_time = util::process_start_time(pid);
        if (process_time == INVALID_TIME) return SSCAN_ERROR0; //skip process if cannot retrieve the time

        // if HH was started after the process
        if (this->initTime > process_time) {
            time_diff = this->initTime - process_time;
            if (time_diff > hh_args.ptimes) return SSCAN_NOT_MATCH; // skip process created before the supplied time
        }
    }
    //filter by the names/PIDs
    if (hh_args.names_list.size() || hh_args.pids_list.size()) {
        if (!util::is_searched_name(exe_file, hh_args.names_list) && !util::is_searched_pid(pid, hh_args.pids_list)) {
            //it is not the searched process, so skip it
            return SSCAN_NOT_MATCH;
        }
        found = true;
    }
    if (!found && hh_args.ignored_names_list.size()) {
        if (util::is_searched_name(exe_file, hh_args.ignored_names_list)) {
            return SSCAN_IGNORED;
        }
    }
    if (!hh_args.quiet) {
        const std::lock_guard<std::mutex> stdOutLock(g_stdOutMutex);
        std::cout << ">> Scanning PID: " << std::setw(PID_FIELD_SIZE) << std::dec << pid;
        std::wcout << " : " << exe_file;

        if (is_process_wow64) {
            std::cout << " : 32b";
        }
        if (check_time) {
            std::cout << " : " << time_diff << "s";
        }
        std::cout << std::endl;
    }
    //perform the scan:
    pesieve::t_params &pesieve_args = this->hh_args.pesieve_args;
    pesieve_args.pid = pid;

    pesieve::t_report report = PESieve_scan(pesieve_args);
    my_report.appendReport(report, exe_file);

    printSingleReport(report);
    if (report.scanned > 0) {
        return SSCAN_SUCCESS;
    }
    return SSCAN_ERROR1;
}

HHScanReport* HHScanner::scan()
{
    const time_t scan_start = time(NULL); //start time of the current scan
    pesieve::t_params &pesieve_args = this->hh_args.pesieve_args;
    initOutDir(scan_start, pesieve_args);

    HHScanReport *my_report = new HHScanReport(GetTickCount(), scan_start);
    scanProcesses(*my_report);

    my_report->setEndTick(GetTickCount(), time(NULL));
    return my_report;
}

bool HHScanner::writeToLog(HHScanReport* hh_report)
{
    if (!hh_args.log) {
        return false;
    }

    const bool suspiciousOnly = false;

    std::string summary_str;
    summary_str = hh_report->toString(suspiciousOnly);

    static std::mutex logMutx;
    const std::lock_guard<std::mutex> lock(logMutx);
    return files_util::write_to_file("hollows_hunter.log", summary_str, true);
}

void HHScanner::summarizeScan(HHScanReport *hh_report, bool suspiciousOnly)
{
    if (!hh_report) return;
    std::string summary_str;

    if (!this->hh_args.json_output) {
        summary_str = hh_report->toString(suspiciousOnly);
        std::cout << summary_str;
    }
    else {
        summary_str = hh_report->toJSON(this->hh_args);
        std::cout << summary_str;
    }

    if (hh_args.pesieve_args.out_filter != OUT_NO_DIR) {
        //file the same report into the directory with dumps:
        if (hh_report->suspicious.size()) {
            std::string report_path = files_util::join_path(this->outDir, "summary.json");

            static std::mutex summaryMutx;
            const std::lock_guard<std::mutex> lock(summaryMutx);
            //TODO: fix JSON formatting for the appended reports
            files_util::write_to_file(report_path, hh_report->toJSON(this->hh_args), true);
        }
    }
    if (hh_args.log) {
        writeToLog(hh_report);
    }
    if (hh_args.suspend_suspicious) {
        process_util::suspend_suspicious(hh_report->suspicious);
    }
    if (hh_args.kill_suspicious) {
       process_util::kill_suspicious(hh_report->suspicious);
    }
}
