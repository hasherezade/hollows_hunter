#include "hh_report.h"

#include <string>
#include <sstream>
#include <codecvt>
#include <locale>
#include <iostream>
#include <iomanip>
#include <cmath>

#include "util/time_util.h"

#define OUT_PADDED(stream, field_size, str) \
std::cout.fill(' '); \
if (field_size) stream << std::setw(field_size) << ' '; \
stream << str;


bool HHScanReport::appendReport(pesieve::t_report &scan_report, const std::wstring &img_name)
{
    pidToReport[scan_report.pid] = scan_report;
    pidToName[scan_report.pid] = img_name;
    if (scan_report.suspicious) {
        this->suspicious.push_back(scan_report.pid);
    }
    if (scan_report.errors == pesieve::ERROR_SCAN_FAILURE) {
        this->failed.push_back(scan_report.pid);
    }
    return true;
}

size_t HHScanReport::reportsToString(std::wstringstream& stream, const pesieve::t_results_filter rfilter)
{
    if (rfilter == pesieve::SHOW_NONE) {
        return 0;
    }
    size_t printed = 0;
    size_t counter = 0;
    size_t scannedCount = countReports(rfilter);

    if (!scannedCount) {
        return printed;
    }

    const size_t max_len = size_t(std::floor(std::log10(double(scannedCount))) + 1) % 100;
    for (auto itr = this->pidToReport.begin(); itr != pidToReport.end(); ++itr) {
        bool isFailed = false;
        DWORD pid = itr->first;
        pesieve::t_report rep = itr->second;
        if ((rfilter & pesieve::SHOW_SUSPICIOUS) == 0) {
            if (rep.suspicious) continue;
        }
        if ((rfilter & pesieve::SHOW_NOT_SUSPICIOUS) == 0) {
            if (!rep.suspicious) continue;
        }
        if (rep.errors == pesieve::ERROR_SCAN_FAILURE) {
            isFailed = true;
        }
        
        if (isFailed && ((rfilter & pesieve::SHOW_ERRORS) == 0)) {
            continue; // do not display failed
        }
        stream << L"[" << std::setw(max_len) << counter++ << L"]: PID: " << std::dec << pid << L", ";
        stream << L"Name: " << this->pidToName[pid];
        if (isFailed) {
            stream << L" : FAILED";
        }
        stream << L"\n";
        printed++;
    }
    return printed;
}

size_t HHScanReport::reportsToJSON(std::wstringstream &stream, size_t level, const t_hh_params &params)
{
    std::vector<DWORD>::const_iterator itr;
    OUT_PADDED(stream, level, L"\"suspicious\" : [\n");
    level++;
    size_t printed = 0;
    for (itr = this->suspicious.begin(); itr != suspicious.end(); ++itr) {
        DWORD pid = *itr;
        OUT_PADDED(stream, level, L"{\n");
        level++;

        OUT_PADDED(stream, level, L"\"pid\" : ");
        stream << std::dec << pid << L",\n";
        OUT_PADDED(stream, level, L"\"is_managed\" : ");
        stream << std::dec << pidToReport[pid].is_managed << L",\n";
        OUT_PADDED(stream, level, L"\"name\" : ");
        stream << L"\"" << this->pidToName[pid] << L"\",\n";
        OUT_PADDED(stream, level, L"\"replaced\" : ");
        stream << std::dec << pidToReport[pid].replaced << L",\n";
        OUT_PADDED(stream, level, L"\"hdr_modified\" : ");
        stream << std::dec << pidToReport[pid].hdr_mod << L",\n";
        if (!params.pesieve_args.no_hooks) {
            OUT_PADDED(stream, level, L"\"patched\" : ");
            stream << std::dec << pidToReport[pid].patched << L",\n";
        }
        if (params.pesieve_args.iat != pesieve::PE_IATS_NONE) {
            OUT_PADDED(stream, level, L"\"iat_hooked\" : ");
            stream << std::dec << pidToReport[pid].iat_hooked << L",\n";
        }
        OUT_PADDED(stream, level, L"\"implanted_pe\" : ");
        stream << std::dec << pidToReport[pid].implanted_pe << L",\n";
        OUT_PADDED(stream, level, L"\"implanted_shc\" : ");
        stream << std::dec << pidToReport[pid].implanted_shc << L",\n";
        OUT_PADDED(stream, level, L"\"unreachable_file\" : ");
        stream << std::dec << pidToReport[pid].unreachable_file << L",\n";
        OUT_PADDED(stream, level, L"\"other\" : ");
        stream << std::dec << pidToReport[pid].other << L"\n";
        level--;
        OUT_PADDED(stream, level, L"}");
        printed++;
        if (printed < suspicious.size()) {
            stream << L",";
        }
        stream << L"\n";
    }
    level--;
    OUT_PADDED(stream, level, L"]\n");
    return printed;
}

size_t HHScanReport::toJSON(std::wstringstream &stream, const t_hh_params &params)
{
    size_t level = 0;
    OUT_PADDED(stream, level, L"{\n");
    level++;
    //summary:
    const size_t suspicious_count = countReports(pesieve::SHOW_SUSPICIOUS);
    size_t all_count = 0;
    OUT_PADDED(stream, level, L"\"scan_date_time\" : ");
    stream << std::dec << L"\"" << util::strtime(this->startTime) << L"\"" << L",\n";
    OUT_PADDED(stream, level, L"\"scan_timestamp\" : ");
    stream << std::dec << startTime << L",\n";
    OUT_PADDED(stream, level, L"\"scan_time_ms\" : ");
    stream << std::dec << getScanTime() << L",\n";
    OUT_PADDED(stream, level, L"\"scanned_count\" : ");
    stream << std::dec << countTotal(true) << L",\n";
    OUT_PADDED(stream, level, L"\"failed_count\" : ");
    stream << std::dec << countReports(pesieve::SHOW_ERRORS) << L",\n";
    OUT_PADDED(stream, level, L"\"suspicious_count\" : ");
    stream << std::dec << suspicious_count;
    if (suspicious_count > 0) {
        stream << L",\n";
        all_count = reportsToJSON(stream, level, params);
    }
    else {
        stream << L"\n";
    }
    level--;
    OUT_PADDED(stream, level, L"}\n");
    return all_count;
}

template<class STR_STREAM>
void print_scantime(STR_STREAM& stream, size_t timeInMs)
{
    float seconds = ((float)timeInMs / 1000);
    float minutes = ((float)timeInMs / 60000);
    stream << std::dec << timeInMs << L" ms.";
    if (seconds > 0.5) {
        stream << L" = " << seconds << L" sec.";
    }
    if (minutes > 0.5) {
        stream << L" = " << minutes << L" min.";
    }
}

void HHScanReport::toString(std::wstringstream &stream, const pesieve::t_results_filter rfilter)
{
    //summary:
    stream << L"--------" << std::endl;
    stream << L"SUMMARY:\n";
    stream << L"Scan at: " << util::strtime(this->startTime) << L" (" << std::dec << startTime << L")\n";
    stream << L"Finished scan in: ";
    print_scantime(stream, getScanTime());
    stream << L"\n";
    const size_t scannedCount = countReports(pesieve::SHOW_SUCCESSFUL_ONLY);
    stream << L"[*] Total scanned: " << std::dec << scannedCount << L"\n";
    if ((rfilter & pesieve::SHOW_NOT_SUSPICIOUS) && scannedCount > 0) {
        stream << L"[+] List of scanned: \n";
        reportsToString(stream, pesieve::SHOW_SUCCESSFUL_ONLY);
    }
    if (rfilter & pesieve::SHOW_SUSPICIOUS) {
        const size_t count = countReports(pesieve::SHOW_SUSPICIOUS);
        stream << L"[*] Total suspicious: " << std::dec << count << L"\n";
        if (count > 0) {
            stream << L"[+] List of suspicious: \n";
            reportsToString(stream, pesieve::SHOW_SUSPICIOUS);
        }
    }
    if (rfilter & pesieve::SHOW_ERRORS) {
        const size_t count = countReports(pesieve::SHOW_ERRORS);
        stream << L"[*] Total failed: " << std::dec << count << L"\n";
    }
}
