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

bool is_suspicious_process(pesieve::t_report report)
{
    if (report.suspicious) {
        return true;
    }
    return false;
}

bool HHScanReport::appendReport(pesieve::t_report &scan_report, const std::wstring &img_name)
{
    pidToReport[scan_report.pid] = scan_report;
    pidToName[scan_report.pid] = img_name;
    if (is_suspicious_process(scan_report)) {
        this->suspicious.push_back(scan_report.pid);
    }
    return true;
}

size_t HHScanReport::reportsToString(std::wstringstream& stream, bool suspiciousOnly)
{
    size_t printed = 0;
    size_t counter = 0;
    size_t scannedCount = pidToReport.size();
    if (suspiciousOnly) {
        scannedCount = suspicious.size();
    }
    if (!scannedCount) {
        return printed;
    }
    const size_t max_len = size_t(std::floor(std::log10(double(scannedCount - 1))) + 1);
    for (auto itr = this->pidToReport.begin(); itr != pidToReport.end(); ++itr) {
        DWORD pid = itr->first;
        if (suspiciousOnly) {
            pesieve::t_report rep = itr->second;
            if (!rep.suspicious) continue;
        }
        stream << L"[" << std::setw(max_len) << counter++ << L"]: PID: " << std::dec << pid << L", ";
        stream << L"Name: " << this->pidToName[pid] << L"\n";
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

std::string HHScanReport::toJSON(const t_hh_params &params)
{
    std::wstringstream stream;
    size_t level = 0;
    OUT_PADDED(stream, level, L"{\n");
    level++;
    //summary:
    const size_t suspicious_count = countSuspicious();

    OUT_PADDED(stream, level, L"\"scan_date_time\" : ");
    stream << std::dec << L"\"" << util::strtime(this->startTime) << L"\"" << L",\n";
    OUT_PADDED(stream, level, L"\"scan_timestamp\" : ");
    stream << std::dec << startTime << L",\n";
    OUT_PADDED(stream, level, L"\"scan_time_ms\" : ");
    stream << std::dec << getScanTime() << L",\n";
    OUT_PADDED(stream, level, L"\"scanned_count\" : ");
    stream << std::dec << countTotal() << L",\n";
    OUT_PADDED(stream, level, L"\"suspicious_count\" : ");
    stream << std::dec << suspicious_count;
    if (suspicious_count > 0) {
        stream << L",\n";
        reportsToJSON(stream, level, params);
    }
    else {
        stream << L"\n";
    }
    level--;
    OUT_PADDED(stream, level, L"}\n");
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(stream.str());
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

std::string HHScanReport::toString(bool suspiciousOnly)
{
    std::wstringstream stream;
    //summary:
    stream << L"--------" << std::endl;
    stream << L"SUMMARY:\n";
    stream << L"Scan at: " << util::strtime(this->startTime) << L" (" << std::dec << startTime << L")\n";
    stream << L"Finished scan in: ";
    print_scantime(stream, getScanTime());
    stream << L"\n";
    stream << L"[*] Total scanned: " << std::dec << countTotal() << L"\n";
    if (!suspiciousOnly && countTotal() > 0) {
        stream << L"[+] List of scanned: \n";
        reportsToString(stream, false);
    }
    stream << L"[*] Total suspicious: " << std::dec << countSuspicious() << L"\n";
    if (countSuspicious() > 0) {
        stream << L"[+] List of suspicious: \n";
        reportsToString(stream, true);
    }
    return std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(stream.str());
}
